# ----------------------------------------------------------------------------
# ReconMesh Frontend - Dev Mode
# Vite dev server with hot reload, watching src files via bind mount.
# Production build is separate (Phase 5+).
# ----------------------------------------------------------------------------
FROM node:22-alpine

# Working directory inside the container
WORKDIR /app

# Set Node to development mode
ENV NODE_ENV=development

# Vite dev server defaults
ENV HOST=0.0.0.0
ENV PORT=5173

# Make /app owned by node user before any user switch
# (WORKDIR creates it as root by default — we hand it over to node)
RUN chown -R node:node /app

# Switch to non-root user before installing
USER node

# Copy package files (now as node, with proper ownership)
COPY --chown=node:node package.json package-lock.json ./

# Install dependencies
RUN npm install

# Copy the rest of the frontend source
COPY --chown=node:node . .

# Expose the Vite dev server port
EXPOSE 5173

# Start the dev server, bound to all interfaces so Docker can route to it
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]