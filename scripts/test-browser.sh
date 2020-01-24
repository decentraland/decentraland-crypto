env PORT_TO_USE=3001 ./node_modules/.bin/ts-node test/server/server.ts \
& npm run test:browsers \
&& kill $(lsof -t -i:3001)