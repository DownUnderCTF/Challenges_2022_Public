#!/bin/bash

docker build -t uni-of-straya . && \
docker run -it -p 8080:8080 --rm --name uni-of-straya-container uni-of-straya