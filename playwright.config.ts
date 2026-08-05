// playwright.config.ts
import { defineConfig, devices, PlaywrightTestConfig } from '@playwright/test';

const config: PlaywrightTestConfig = defineConfig({
  testDir: './test',
  projects: [
    {
      name: 'chrome-canary-pqc',
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chrome-canary',
        launchOptions: {
          args: [
            '--enable-automation',
            '--enable-experimental-web-platform-features',
            '--enable-features=WebCryptoPQC',
            '--enable-blink-features=WebCryptoPQC',
          ],
        },
      },
    },
  ],
});

export default config;
