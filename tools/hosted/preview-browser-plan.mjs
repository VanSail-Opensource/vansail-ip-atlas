const widths = [320, 390, 1280, 1440]
const themes = ['light', 'dark']

export function previewBrowserPlan(env) {
  const populations = widths.flatMap(width => themes.map(theme => ({ width, theme })))
  const shard = env.ATLAS_PREVIEW_SHARD
  if (shard === undefined) return { populations, queries: true, identity: null }

  const selected = populations.filter(({ width, theme }) => shard === `${width}-${theme}`)
  if (shard !== 'queries' && selected.length !== 1) throw new Error('Unknown preview browser shard')
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REPOSITORY !== 'VanSail-Opensource/vansail-ip-atlas' ||
      env.GITHUB_REF !== 'refs/heads/main' || !/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? '') ||
      !/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ID ?? '') || !/^[1-9][0-9]{0,19}$/.test(env.GITHUB_RUN_ATTEMPT ?? '')) {
    throw new Error('Preview browser shard requires an exact hosted main run and attempt')
  }
  const identity = { schema_version: 1, shard, head_sha: env.GITHUB_SHA, run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT }
  return { populations: selected, queries: shard === 'queries', identity }
}
