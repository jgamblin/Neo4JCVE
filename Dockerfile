# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Install Git
RUN apt-get update && apt-get install -y git && apt-get clean

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run data_collection.py when the container launches
CMD ["python", "data_collection.py"]
