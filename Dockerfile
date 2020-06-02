# Use an official Python runtime as a parent image
FROM python:3.6-slim

WORKDIR /app

COPY requirements.txt ./
COPY arbor-monitor ./arbor-monitor/

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt
