FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN mkdir -p uploads && touch domains.json && echo '{}' > domains.json

EXPOSE 7860

ENV PORT=7860
ENV NODE_ENV=production

CMD ["node", "server.js"]
