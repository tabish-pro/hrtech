# Use an official Node.js runtime as a parent image
FROM node:18-alpine

# Set the working directory in the container
WORKDIR /app

# Copy package.json and package-lock.json to the container
# This allows caching of node_modules layer if package files don't change
COPY package*.json ./

# Install application dependencies
# Using `npm ci` for clean and consistent installations in CI/CD environments
RUN npm ci

# Copy the rest of the application code to the container
COPY . .

# Expose the port the app runs on (default is 3000 as per server.js)
EXPOSE 3000

# Command to run the application
# Use 'npm start' as defined in package.json
# Install wait-on for database readiness check
RUN npm install -g wait-on

# Command to run the application, waiting for the database to be ready
CMD wait-on tcp:db:5432 && npm start
