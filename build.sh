#!/bin/bash

ACCOUNT_ID=931174280450
REGION=us-east-1
REPO_NAME=my-app
ECR_URL="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME"

# Authenticate Docker to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build, tag, and push
docker build -t $REPO_NAME .
docker tag $REPO_NAME $ECR_URL
docker push $ECR_URL
