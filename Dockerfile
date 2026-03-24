FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm install

RUN npm install -g openclaw

COPY . .

ENV NEXT_TELEMETRY_DISABLED=1

CMD ["npm", "run", "dev"]