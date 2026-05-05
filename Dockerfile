FROM node:22-alpine

WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY src ./src
COPY public ./public
COPY README.md ./

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
