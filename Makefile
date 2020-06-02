DOCKER_REGISTRY := community.cablelabs.com:4567
DOCKER_IMAGE_PATH := dis-docker/dis-arbor-monitor:latest

docker-build:
	docker build -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH) .

docker-push:
	docker login $(DOCKER_REGISTRY)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH)
