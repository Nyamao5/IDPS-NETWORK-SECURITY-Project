#!/bin/bash

echo "IDPS Network Security - Quick Build Script"
echo "=========================================="

# Create shared directories
echo "Creating shared directories..."
mkdir -p ./shared/logs ./shared/pcaps ./shared/reports ./shared/analysis ./shared/monitoring

# Pull base images in advance (speeds up build process)
echo "Pulling base images..."
docker pull ubuntu:22.04
docker pull debian:bullseye-slim

# Build with optimizations
echo "Building containers with optimizations..."
docker-compose build --parallel --no-cache

echo "Build complete. Run with: docker-compose up"