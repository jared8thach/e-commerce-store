import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    reporters: ['junit', 'json', 'html', 'default'],
    outputFile: {
      junit: './artifacts/junit/junit-report.xml',
      json: './artifacts/json/json-report.json',
      html: './artifacts/html/html-report.html',
    },
    coverage: {
        provider: 'v8'
    }
  },
})