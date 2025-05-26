@echo off
echo IDPS Network Security - Minimal Build Script
echo ==========================================

echo Creating shared directories...
mkdir shared\logs shared\pcaps shared\monitoring 2>nul

echo Setting Docker build optimization flags...
set DOCKER_BUILDKIT=1
set COMPOSE_DOCKER_CLI_BUILD=1

echo Pulling minimal base image...
docker pull debian:bullseye-slim

echo Building minimal environment (web-server only first)...
docker-compose build --no-cache web-server

echo Starting web-server container...
docker-compose up -d web-server

echo Web server is now running. To build and start other containers, run:
echo docker-compose build attacker
echo docker-compose up -d attacker
echo.
echo When you're ready to build the IDPS system:
echo docker-compose build idps
echo docker-compose up -d idps

echo.
echo You can now use the web-server at http://localhost