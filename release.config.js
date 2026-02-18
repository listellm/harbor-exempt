module.exports = {
  branches: ['main'],
  plugins: [
    [
      '@semantic-release/commit-analyzer',
      {
        preset: 'conventionalcommits',
        releaseRules: [
          { type: 'breaking', release: 'major' },
          { type: 'feat', release: 'minor' },
          { type: 'fix', release: 'patch' }
        ]
      }
    ],
    [
      '@semantic-release/release-notes-generator',
      {
        preset: 'conventionalcommits',
        presetConfig: {
          types: [
            {
              type: 'breaking',
              section: '💥 Breaking Changes',
              hidden: false
            },
            {
              type: 'feat',
              section: '✨ Features',
              hidden: false
            },
            {
              type: 'fix',
              section: '🐛 Bug Fixes',
              hidden: false
            }
          ]
        }
      }
    ],
    [
      '@semantic-release/github',
      {
        assets: []
      }
    ]
  ]
}
