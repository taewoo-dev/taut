use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

type Value = (u16, u16, Vec<String>, Vec<String>, u16);
type Row = (String, String, Vec<String>, Value);
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
struct Summary {
    effects: u16,
    direct: u16,
    providers: BTreeSet<String>,
    bulk: BTreeSet<String>,
    uncertain: u16,
}
impl Summary {
    fn parse(v: Value) -> Result<Self, String> {
        if v.0 > 255 || v.1 & !v.0 != 0 || v.4 > 255 {
            return Err("invalid effect masks".into());
        }
        Ok(Self {
            effects: v.0,
            direct: v.1,
            providers: v.2.into_iter().collect(),
            bulk: v.3.into_iter().collect(),
            uncertain: v.4,
        })
    }
    fn merge(&mut self, other: &Self) {
        self.effects |= other.effects;
        self.direct |= other.direct;
        self.uncertain |= other.uncertain;
        self.providers.extend(other.providers.iter().cloned());
        self.bulk.extend(other.bulk.iter().cloned());
    }
    fn export(&self) -> Value {
        (
            self.effects,
            self.direct,
            self.providers.iter().cloned().collect(),
            self.bulk.iter().cloned().collect(),
            self.uncertain,
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Function {
    module: String,
    callees: Vec<String>,
    direct: Summary,
}
#[pyclass(frozen, weakref)]
struct State {
    functions: BTreeMap<String, Arc<Function>>,
    summaries: BTreeMap<String, Arc<Summary>>,
    graph: Vec<Vec<usize>>,
    reverse: Vec<Vec<usize>>,
    #[pyo3(get)]
    reused_components: usize,
    #[pyo3(get)]
    recomputed_components: usize,
    #[pyo3(get)]
    compute_seconds: f64,
}
fn calculate(
    previous: Option<&State>,
    changed: Vec<String>,
    rows: Vec<Row>,
) -> Result<State, String> {
    let started = Instant::now();
    let changed: BTreeSet<_> = changed.into_iter().collect();
    let mut functions = previous.map(|p| p.functions.clone()).unwrap_or_default();
    functions.retain(|_, f| !changed.contains(&f.module));
    let mut seen = BTreeSet::new();
    for (name, module, mut callees, value) in rows {
        if name.is_empty()
            || module.is_empty()
            || !seen.insert(name.clone())
            || (previous.is_some() && !changed.contains(&module))
        {
            return Err("invalid or duplicate function, or module outside changed batch".into());
        }
        callees.sort();
        callees.dedup();
        functions.insert(
            name,
            Arc::new(Function {
                module,
                callees,
                direct: Summary::parse(value)?,
            }),
        );
    }
    let names: Vec<_> = functions.keys().cloned().collect();
    let ids: HashMap<_, _> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();
    let graph: Vec<Vec<usize>> = names
        .iter()
        .map(|n| {
            functions[n]
                .callees
                .iter()
                .filter_map(|c| ids.get(c.as_str()).copied())
                .collect()
        })
        .collect();
    let mut reverse = vec![vec![]; names.len()];
    for (i, edges) in graph.iter().enumerate() {
        for &j in edges {
            reverse[j].push(i);
        }
    }
    let mut visited = vec![false; names.len()];
    let mut finished = Vec::new();
    for start in 0..names.len() {
        let mut stack = vec![(start, false)];
        while let Some((node, exiting)) = stack.pop() {
            if exiting {
                finished.push(node);
                continue;
            }
            if visited[node] {
                continue;
            }
            visited[node] = true;
            stack.push((node, true));
            for &target in graph[node].iter().rev() {
                if !visited[target] {
                    stack.push((target, false));
                }
            }
        }
    }
    let mut assigned = vec![false; names.len()];
    let mut components = Vec::new();
    for &start in finished.iter().rev() {
        if assigned[start] {
            continue;
        }
        assigned[start] = true;
        let mut pending = vec![start];
        let mut members = Vec::new();
        while let Some(node) = pending.pop() {
            members.push(node);
            for &source in &reverse[node] {
                if !assigned[source] {
                    assigned[source] = true;
                    pending.push(source);
                }
            }
        }
        members.sort();
        components.push(members);
    }
    components.sort();
    let mut owner = vec![0; names.len()];
    for (i, c) in components.iter().enumerate() {
        for &node in c {
            owner[node] = i;
        }
    }
    let mut outgoing = vec![BTreeSet::new(); components.len()];
    let mut dependents = vec![BTreeSet::new(); components.len()];
    for (i, edges) in graph.iter().enumerate() {
        for &j in edges {
            if owner[i] != owner[j] {
                outgoing[owner[i]].insert(owner[j]);
                dependents[owner[j]].insert(owner[i]);
            }
        }
    }
    // Include both old and new reverse edges: removed calls can remove propagated effects.
    let mut affected = BTreeSet::new();
    if let Some(prior) = previous {
        let mut backwards: HashMap<&str, Vec<&str>> = HashMap::new();
        for (name, f) in functions.iter().chain(prior.functions.iter()) {
            for c in &f.callees {
                backwards.entry(c).or_default().push(name);
            }
        }
        for name in functions.keys().chain(prior.functions.keys()) {
            if functions.get(name) != prior.functions.get(name) {
                affected.insert(name.clone());
            }
        }
        let mut pending: Vec<_> = affected.iter().cloned().collect();
        while let Some(node) = pending.pop() {
            if let Some(callers) = backwards.get(node.as_str()) {
                for &caller in callers {
                    if affected.insert(caller.to_owned()) {
                        pending.push(caller.to_owned());
                    }
                }
            }
        }
    } else {
        affected.extend(names.iter().cloned());
    }
    let mut remaining: Vec<_> = outgoing.iter().map(BTreeSet::len).collect();
    let mut ready: BTreeSet<_> = remaining
        .iter()
        .enumerate()
        .filter_map(|(i, &n)| (n == 0).then_some(i))
        .collect();
    let empty = Arc::new(Summary::default());
    let mut values: Vec<Arc<Summary>> = vec![empty; components.len()];
    let mut pool: HashMap<Summary, Arc<Summary>> = HashMap::new();
    let mut reused = 0;
    let mut recomputed = 0;
    while let Some(i) = ready.pop_first() {
        let cached = previous
            .filter(|_| components[i].iter().all(|&n| !affected.contains(&names[n])))
            .and_then(|p| p.summaries.get(&names[components[i][0]]));
        let value = if let Some(v) = cached {
            reused += 1;
            Arc::clone(pool.entry((**v).clone()).or_insert_with(|| Arc::clone(v)))
        } else {
            recomputed += 1;
            let mut v = Summary::default();
            for &n in &components[i] {
                v.merge(&functions[&names[n]].direct);
            }
            for &j in &outgoing[i] {
                v.merge(&values[j]);
            }
            Arc::clone(pool.entry(v.clone()).or_insert_with(|| Arc::new(v)))
        };
        values[i] = value;
        for &j in &dependents[i] {
            remaining[j] -= 1;
            if remaining[j] == 0 {
                ready.insert(j);
            }
        }
    }
    let summaries = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), Arc::clone(&values[owner[i]])))
        .collect();
    Ok(State {
        functions,
        summaries,
        graph,
        reverse,
        reused_components: reused,
        recomputed_components: recomputed,
        compute_seconds: started.elapsed().as_secs_f64(),
    })
}
#[pymethods]
impl State {
    #[staticmethod]
    fn build(py: Python<'_>, rows: Vec<Row>) -> PyResult<Self> {
        py.detach(move || calculate(None, vec![], rows))
            .map_err(PyValueError::new_err)
    }
    fn advance(
        &self,
        py: Python<'_>,
        changed_modules: Vec<String>,
        rows: Vec<Row>,
    ) -> PyResult<Self> {
        py.detach(move || calculate(Some(self), changed_modules, rows))
            .map_err(PyValueError::new_err)
    }
    fn export(&self) -> Vec<(String, Value)> {
        self.summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.export()))
            .collect()
    }
    fn export_compact(&self) -> (Vec<Value>, Vec<(String, usize)>) {
        let mut ids = HashMap::new();
        let mut values = Vec::new();
        let rows = self
            .summaries
            .iter()
            .map(|(name, summary)| {
                let index = *ids.entry(Arc::as_ptr(summary)).or_insert_with(|| {
                    let index = values.len();
                    values.push(summary.export());
                    index
                });
                (name.clone(), index)
            })
            .collect();
        (values, rows)
    }
    fn export_direct(&self) -> Vec<(String, Value)> {
        self.functions
            .iter()
            .map(|(n, f)| (n.clone(), f.direct.export()))
            .collect()
    }
    fn export_graph(&self) -> Vec<(String, Vec<String>)> {
        let names: Vec<_> = self.functions.keys().collect();
        names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    (*n).clone(),
                    self.graph[i].iter().map(|&j| names[j].clone()).collect(),
                )
            })
            .collect()
    }
    fn stats(&self) -> (usize, usize, usize, usize) {
        let unique: BTreeSet<_> = self.summaries.values().map(Arc::as_ptr).collect();
        (
            self.functions.len(),
            self.graph.iter().map(Vec::len).sum(),
            self.reverse.iter().map(Vec::len).sum(),
            unique.len(),
        )
    }
}
#[pymodule]
fn _taut_summary_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("CONTRACT_VERSION", 1)?;
    m.add_class::<State>()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(name: &str, calls: &[&str], effects: u16) -> Row {
        (
            name.into(),
            "m".into(),
            calls.iter().map(|s| (*s).into()).collect(),
            (effects, effects, vec![], vec![], 0),
        )
    }
    #[test]
    fn cycle_removal_and_failure_are_immutable() {
        let old = calculate(None, vec![], vec![row("a", &["b"], 0), row("b", &["a"], 1)]).unwrap();
        assert_eq!(old.summaries["a"].effects, 1);
        let new = calculate(Some(&old), vec!["m".into()], vec![row("a", &[], 0)]).unwrap();
        assert_eq!(new.summaries["a"].effects, 0);
        assert_eq!(old.summaries["a"].effects, 1);
        assert!(calculate(Some(&old), vec![], vec![row("a", &[], 0)]).is_err());
    }
    #[test]
    fn changed_and_reused_equal_values_share() {
        let old = calculate(
            None,
            vec![],
            vec![
                ("a.f".into(), "a".into(), vec![], (0, 0, vec![], vec![], 0)),
                ("b.f".into(), "b".into(), vec![], (1, 1, vec![], vec![], 0)),
            ],
        )
        .unwrap();
        let new = calculate(
            Some(&old),
            vec!["b".into()],
            vec![("b.f".into(), "b".into(), vec![], (0, 0, vec![], vec![], 0))],
        )
        .unwrap();
        assert_eq!(new.stats().3, 1);
        assert_eq!(old.stats().3, 2);
    }
    #[test]
    fn deep_chain_is_iterative() {
        let rows = (0..10000)
            .map(|i| {
                (
                    format!("f{i}"),
                    "m".into(),
                    if i == 9999 {
                        vec![]
                    } else {
                        vec![format!("f{}", i + 1)]
                    },
                    (1, 1, vec![], vec![], 0),
                )
            })
            .collect();
        let s = calculate(None, vec![], rows).unwrap();
        assert_eq!(s.summaries.len(), 10000);
        assert_eq!(s.stats().3, 1);
    }
}
