// PP-G03: an unassigned property is compiled. Template engines compile their input, so
// a forged default is server-side template injection rather than stored markup.
export function renderView(engine, view) {
  const compiled = engine.compile(view.layoutSource);
  return compiled({ title: 'Report' });
}
