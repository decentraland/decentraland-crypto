env PORT_TO_USE=3001 ./node_modules/.bin/ts-node test/server/server.ts\
& env PORT_TO_USE=3001 npm run test:all-browsers \
&& env PORT_TO_USE=3001 npm run test:node