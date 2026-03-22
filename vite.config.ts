/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import {defineConfig} from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
    build: {
        lib: {
            entry: 'src/index.ts',
            formats: ['es', 'cjs'],
            fileName: (format) => format === 'es' ? 'index.js' : 'index.cjs'
        },
        rollupOptions: {
            external: ["crypto"],
            output: {
                exports: 'named',
            },
        },
        sourcemap: true,
        target: 'node22'
    },
    plugins: [dts()]
});
