# --- Stage 0: Source Cloner ---
# Use a lightweight image that includes Git to clone the repository.
# This stage's only purpose is to fetch the latest source code.
FROM alpine/git AS source-cloner

# Set a working directory inside this stage.
WORKDIR /app

# Add a build argument that can be changed to invalidate the Docker cache.
# This ensures that a fresh 'git clone' is performed when needed.
ARG CACHE_BUSTER=1

# Clone the entire GitHub repository into the current working directory (/app).
RUN git clone https://github.com/bodybuildingfly/trello-card-scheduler.git .

# --- Stage 1: Build the React Frontend ---
# Use a Node.js image for building the React frontend.
FROM node:18-alpine AS build-stage

# Set the working directory for the frontend build.
WORKDIR /app/frontend

# Copy only the package files from the source-cloner stage first.
# This leverages Docker's layer caching for faster subsequent builds if dependencies haven't changed.
COPY --from=source-cloner /app/frontend/package*.json ./
RUN npm install

# Copy the rest of the frontend source code from the cloner stage.
COPY --from=source-cloner /app/frontend/ ./

# Build the static files for production. The output will be in /app/frontend/build.
RUN npm run build


# --- Stage 2: Create the Final Node.js Server Image ---
# Start from a fresh, clean Node.js image for the final production environment.
FROM node:18-alpine

# Set the working directory for the final application.
WORKDIR /app

# Set the environment to production. This tells Express to run in an optimized mode.
ENV NODE_ENV=production

# Copy the backend's package files from the cloner stage.
COPY --from=source-cloner /app/backend/package*.json ./backend/

# Install only production dependencies to keep the final image small and secure.
RUN npm install --prefix backend --production

# Copy the rest of the backend source code from the cloner stage.
COPY --from=source-cloner /app/backend/ ./backend/

# Copy the built static files from the 'build-stage' into a 'build' folder
# that the Express server will use to serve the frontend.
COPY --from=build-stage /app/frontend/build ./build

# The server will run on port 5000 inside the container.
EXPOSE 5000

# The command to start the Node.js server in production mode.
CMD ["npm", "start", "--prefix", "backend"]