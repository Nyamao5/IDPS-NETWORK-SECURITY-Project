@echo off
echo IDPS Network Security - Quick Build Script
echo ==========================================

echo Creating shared directories...
mkdir shared\logs shared\pcaps shared\reports shared\analysis shared\monitoring 2>nul

echo Pulling base images...
docker pull ubuntu:22.04
docker pull debian:bullseye-slim

echo Building containers with optimizations...
docker-compose build --parallel

echo Build complete. Run with: docker-compose up