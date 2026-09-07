use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

type Range = (u8, u8);
type Contribution = (Range, Option<String>, Vec<String>);
type Function = (String, String, Vec<String>);
type Calls = (
    Vec<String>,
    Vec<String>,
    Vec<Option<String>>,
    Vec<Option<String>>,
    Vec<Vec<String>>,
    Vec<String>,
    Vec<Vec<String>>,
    Vec<u8>,
);
type Batch = (
    Vec<Function>,
    Calls,
    Vec<(String, Vec<String>)>,
    Vec<String>,
    Vec<String>,
);
const WRITES: &[&str] = &[
    "add",
    "add_all",
    "bulk_create",
    "bulk_update",
    "create",
    "delete",
    "flush",
    "get_or_create",
    "merge",
    "save",
    "update",
    "update_or_create",
];
#[derive(Clone, Eq, PartialEq)]
struct Entry {
    module: String,
    contributions: Vec<Contribution>,
}
#[pyclass(frozen, weakref)]
pub struct AtomicState {
    entries: BTreeMap<String, Arc<Entry>>,
    summaries: BTreeMap<String, Range>,
    #[pyo3(get)]
    processed_functions: usize,
    #[pyo3(get)]
    compute_seconds: f64,
}
fn calculate(
    prior: Option<&AtomicState>,
    changed: Vec<String>,
    batch: Batch,
) -> Result<AtomicState, String> {
    let started = Instant::now();
    let changed: BTreeSet<_> = changed.into_iter().collect();
    let (functions, calls, grounded, decorators, contexts) = batch;
    let mut entries = prior.map(|p| p.entries.clone()).unwrap_or_default();
    entries.retain(|_, entry| !changed.contains(&entry.module));
    let functions: BTreeMap<_, _> = functions
        .into_iter()
        .map(|(name, module, decorators)| (name, (module, decorators)))
        .collect();
    let owned: BTreeSet<_> = functions.keys().chain(entries.keys()).cloned().collect();
    let grounded: BTreeMap<String, BTreeSet<String>> = grounded
        .into_iter()
        .map(|(m, roots)| (m, roots.into_iter().collect()))
        .collect();
    let mut grouped: BTreeMap<_, Vec<_>> = BTreeMap::new();
    let (owners, modules, raw, canonical, candidates, written, lexical, queries) = calls;
    let count = owners.len();
    if [
        modules.len(),
        raw.len(),
        canonical.len(),
        candidates.len(),
        written.len(),
        lexical.len(),
        queries.len(),
    ]
    .iter()
    .any(|&n| n != count)
    {
        return Err("unequal atomicity-call column lengths".into());
    }
    for (((((((owner, module), raw), canonical), candidates), written), contexts), query) in owners
        .into_iter()
        .zip(modules)
        .zip(raw)
        .zip(canonical)
        .zip(candidates)
        .zip(written)
        .zip(lexical)
        .zip(queries)
    {
        if query > 2 {
            return Err("invalid atomicity query kind".into());
        }
        grouped
            .entry((owner, module))
            .or_default()
            .push((raw, canonical, candidates, written, contexts, query));
    }
    for (name, (module, decorated)) in functions {
        if name.is_empty() || module.is_empty() || (prior.is_some() && !changed.contains(&module)) {
            return Err("atomicity function outside changed module batch".into());
        }
        let mut contributions = Vec::new();
        if !decorated.iter().any(|s| decorators.iter().any(|b| s == b)) {
            for (raw, canonical, candidates, written, lexical, query) in grouped
                .remove(&(name.clone(), module.clone()))
                .unwrap_or_default()
            {
                if lexical.iter().any(|s| contexts.iter().any(|b| s == b)) {
                    continue;
                }
                let method = written.rsplit('.').next().unwrap_or("");
                let root = written
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .split('(')
                    .next()
                    .unwrap_or("");
                let sql = canonical.as_ref().is_some_and(|s| {
                    s.starts_with("sqlalchemy.")
                        && WRITES.contains(&s.rsplit('.').next().unwrap_or(""))
                });
                let model = WRITES.contains(&method)
                    && grounded
                        .get(&module)
                        .is_some_and(|roots| roots.contains(root));
                let direct = match query {
                    1 => (1, 1),
                    2 => (0, 1),
                    _ if sql || model => (1, 1),
                    _ => (0, 0),
                };
                contributions.push((
                    direct,
                    raw.filter(|s| owned.contains(s)),
                    candidates
                        .into_iter()
                        .filter(|s| owned.contains(s))
                        .collect(),
                ));
            }
        }
        entries.insert(
            name,
            Arc::new(Entry {
                module,
                contributions,
            }),
        );
    }
    let mut affected = BTreeSet::new();
    if let Some(old) = prior {
        for name in entries.keys().chain(old.entries.keys()) {
            if entries.get(name) != old.entries.get(name) {
                affected.insert(name.clone());
            }
        }
    } else {
        affected.extend(entries.keys().cloned());
    }
    let mut reverse: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let empty = BTreeMap::new();
    for (name, entry) in entries
        .iter()
        .chain(prior.map(|p| &p.entries).unwrap_or(&empty).iter())
    {
        for (_, callee, candidates) in &entry.contributions {
            if let Some(callee) = callee {
                reverse.entry(callee).or_default().insert(name);
            } else {
                for c in candidates {
                    reverse.entry(c).or_default().insert(name);
                }
            }
        }
    }
    let mut pending: Vec<_> = affected.iter().cloned().collect();
    while let Some(changed) = pending.pop() {
        if let Some(callers) = reverse.get(changed.as_str()) {
            for &caller in callers {
                if entries.contains_key(caller) && affected.insert(caller.to_owned()) {
                    pending.push(caller.to_owned());
                }
            }
        }
    }
    let mut summaries: BTreeMap<_, _> = entries
        .keys()
        .map(|name| {
            (
                name.clone(),
                if affected.contains(name) {
                    (0, 0)
                } else {
                    prior
                        .and_then(|p| p.summaries.get(name))
                        .copied()
                        .unwrap_or_default()
                },
            )
        })
        .collect();
    let mut queue: BTreeSet<_> = affected
        .iter()
        .filter(|s| entries.contains_key(*s))
        .cloned()
        .collect();
    let edges: usize = affected
        .iter()
        .filter_map(|s| entries.get(s))
        .flat_map(|e| &e.contributions)
        .map(|(_, c, cs)| usize::from(c.is_some()) + cs.len())
        .sum();
    let limit = (affected.len() * 8 + edges * 4).max(1);
    let mut processed = 0;
    while let Some(name) = queue.pop_first() {
        processed += 1;
        if processed > limit {
            return Err("atomicity summary propagation exceeded its bounded work limit".into());
        }
        let mut value: Range = (0, 0);
        for (direct, callee, candidates) in &entries[&name].contributions {
            let child = if let Some(callee) = callee {
                summaries.get(callee).copied().unwrap_or_default()
            } else {
                (
                    0,
                    candidates
                        .iter()
                        .filter_map(|c| summaries.get(c))
                        .map(|r| r.1)
                        .max()
                        .unwrap_or(0),
                )
            };
            value.0 = (value.0 + direct.0 + child.0).min(2);
            value.1 = (value.1 + direct.1 + child.1).min(2);
        }
        if summaries[&name] != value {
            summaries.insert(name.clone(), value);
            if let Some(callers) = reverse.get(name.as_str()) {
                queue.extend(
                    callers
                        .iter()
                        .filter(|c| affected.contains(**c) && entries.contains_key(**c))
                        .map(|c| (*c).to_owned()),
                );
            }
        }
    }
    Ok(AtomicState {
        entries,
        summaries,
        processed_functions: processed,
        compute_seconds: started.elapsed().as_secs_f64(),
    })
}
fn error(message: String) -> PyErr {
    if message.contains("work limit") {
        PyRuntimeError::new_err(message)
    } else {
        PyValueError::new_err(message)
    }
}
#[pymethods]
impl AtomicState {
    #[staticmethod]
    fn build(py: Python<'_>, batch: Batch) -> PyResult<Self> {
        py.detach(move || calculate(None, vec![], batch))
            .map_err(error)
    }
    fn advance(&self, py: Python<'_>, changed: Vec<String>, batch: Batch) -> PyResult<Self> {
        py.detach(move || calculate(Some(self), changed, batch))
            .map_err(error)
    }
    fn export(&self) -> Vec<(String, Range)> {
        self.summaries
            .iter()
            .map(|(s, r)| (s.clone(), *r))
            .collect()
    }
    fn export_contributions(&self) -> Vec<(String, Vec<Contribution>)> {
        self.entries
            .iter()
            .map(|(s, e)| (s.clone(), e.contributions.clone()))
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recursive_writes_and_removal() {
        let functions = vec![("m.f".into(), "m".into(), vec![])];
        let call = (
            vec!["m.f".into()],
            vec!["m".into()],
            vec![Some("m.f".into())],
            vec![Some("m.f".into())],
            vec![vec![]],
            vec!["m.f".into()],
            vec![vec![]],
            vec![1],
        );
        let old = calculate(
            None,
            vec![],
            (functions.clone(), call, vec![], vec![], vec![]),
        )
        .unwrap();
        assert_eq!(old.summaries["m.f"], (2, 2));
        let new = calculate(
            Some(&old),
            vec!["m".into()],
            (functions, Default::default(), vec![], vec![], vec![]),
        )
        .unwrap();
        assert_eq!(new.summaries["m.f"], (0, 0));
        assert_eq!(old.summaries["m.f"], (2, 2));
    }
}
