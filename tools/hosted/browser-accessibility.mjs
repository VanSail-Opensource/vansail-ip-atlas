/** Emit the actual axe engine identity alongside its complete finding counts. */
export async function auditAccessibility(page, axeSource) {
  // Event Timing ends at presentation. Let the UI paint its trusted input
  // before evaluating the audit library or scanning the updated document.
  await page.evaluate(() => new Promise(resolve => {
    requestAnimationFrame(() => requestAnimationFrame(resolve))
  }))
  await page.evaluate(axeSource)
  return page.evaluate(async () => {
    const result = await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })
    return {
      engine: result.testEngine.name,
      version: result.testEngine.version,
      violations: result.violations.map(value => ({ id: value.id, impact: value.impact, nodes: value.nodes.length })),
      incomplete: result.incomplete.map(value => ({ id: value.id, nodes: value.nodes.length })),
    }
  })
}
