# Scripts (prefixed with `npm run ...`)
1. `dev`: starts development server with nodemon watcher
2. `start`: starts server
3. `prettier`: formats entire repository with prettier syntax (should before creating a commit)
4. `build`
5. `test`: executes full vitest suite, using all `reporters` defined in `vitest.config.js` and outputting to their respective `outputFile` destinations
6. `test:ui`: operates exactly as `test` script, but also opens interactive UI