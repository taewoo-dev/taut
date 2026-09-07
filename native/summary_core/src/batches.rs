use crate::{calculate, State, Summary};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub type FunctionRow = (String, String, String); // canonical, lexical, module
pub type Calls = (
    Vec<String>,
    Vec<String>,
    Vec<Option<String>>,
    Vec<String>,
    Vec<u16>,
    Vec<u16>,
    Vec<u16>,
);
pub type Batch = (Vec<FunctionRow>, Calls, Vec<(String, String)>);

pub fn matches(symbol: &str, candidate: &str) -> bool {
    symbol == candidate
        || symbol
            .strip_prefix(candidate)
            .is_some_and(|tail| tail.starts_with('.'))
}

pub fn summarize(
    prior: Option<&State>,
    changed: Vec<String>,
    batch: Batch,
) -> Result<State, String> {
    let started = Instant::now();
    let changed_set: BTreeSet<_> = changed.iter().collect();
    let (functions, calls, providers) = batch;
    let functions: BTreeMap<_, _> = functions
        .into_iter()
        .map(|(canonical, lexical, module)| (canonical, (lexical, module)))
        .collect();
    let mut owned: BTreeSet<_> = functions.keys().cloned().collect();
    if let Some(old) = prior {
        owned.extend(
            old.functions
                .iter()
                .filter(|(_, f)| !changed_set.contains(&f.module))
                .map(|(s, _)| s.clone()),
        );
    }
    let mut grouped: BTreeMap<_, Vec<_>> = BTreeMap::new();
    let (owners, modules, callees, written, effects, direct, uncertain) = calls;
    let count = owners.len();
    if [
        modules.len(),
        callees.len(),
        written.len(),
        effects.len(),
        direct.len(),
        uncertain.len(),
    ]
    .iter()
    .any(|&n| n != count)
    {
        return Err("unequal function-call column lengths".into());
    }
    for ((((((owner, module), callee), written), effects), direct), uncertain) in owners
        .into_iter()
        .zip(modules)
        .zip(callees)
        .zip(written)
        .zip(effects)
        .zip(direct)
        .zip(uncertain)
    {
        // Validate even unowned calls rather than silently accepting corrupt masks.
        Summary::parse((effects, direct, vec![], vec![], uncertain))?;
        grouped
            .entry((owner, module))
            .or_default()
            .push((callee, written, effects, direct, uncertain));
    }
    let mut rows = Vec::with_capacity(functions.len());
    for (canonical, (lexical, module)) in functions {
        let mut value = Summary::default();
        let mut edges = BTreeSet::new();
        for (callee, written, effects, direct, uncertain) in grouped
            .remove(&(lexical, module.clone()))
            .unwrap_or_default()
        {
            value.effects |= effects;
            value.direct |= direct;
            value.uncertain |= uncertain;
            if let Some(callee) = callee {
                if owned.contains(&callee) {
                    edges.insert(callee.clone());
                }
                if let Some((_, canonical_provider)) =
                    providers.iter().find(|(_, p)| matches(&callee, p))
                {
                    value.providers.insert(canonical_provider.clone());
                }
            }
            let operation = written.rsplit('.').next().unwrap_or("");
            if ["asdict", "dict", "model_dump", "model_validate", "vars"].contains(&operation) {
                value.bulk.insert(operation.to_owned());
            }
        }
        rows.push((
            canonical,
            module,
            edges.into_iter().collect(),
            value.export(),
        ));
    }
    let mut state = calculate(prior, changed, rows)?;
    state.compute_seconds = started.elapsed().as_secs_f64();
    Ok(state)
}
