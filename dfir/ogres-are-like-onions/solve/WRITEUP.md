ogres-are-like-onions
============

The provided command will download and run an image

```sh
> docker run -tp 8000:8000 downunderctf/onions
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
The container exposes a web server with a gallery of images http://localhost:8000/

The last image is failing to load. Inspecting its URL reveals memes/flag.jpg,
however it appears to be missing.

Since we know this is a forensics challenge, lets try to dig deeper.


```sh
# List running containers
> docker ps
CONTAINER ID   IMAGE     COMMAND                  CREATED          STATUS          PORTS                    NAMES
24ced4a47790   onions    "/usr/local/bin/pyth…"   38 seconds ago   Up 37 seconds   0.0.0.0:8000->8000/tcp   beautiful_wu

# This will drop up into a terminal inside the running container
> docker exec -it beautiful_wu /bin/sh
/app # ls
Dockerfile  index.html  memes
/app # ls memes
1.jpg     2.jpg     3.jpg     4.jpg
```

Digging around the filesystem here, we will find all the files that make up
the website. This reveals the Dockerfile that built this container image.
But oh no! It tell us that flag.jpg has been deleted!

```dockerfile
# oops that meme is only for me
RUN rm memes/flag.jpg
```

The clue is the pun is the name

Container images are like ogres, they have layers.

Reading about Docker images, you will find that while they act as a snapshot
of a container, they differ a lot from other archive formats (zip, tar, etc.).
Instead of being a flat static copy of the final filesystem, they are gradually
composed during the build stage, with each step forming a new layer with only
the files that have changed. This allows Docker to save space by sharing layers
across images, and save time by not re-building steps that haven't changed.

Because layers are applied on top of each other, the final image actually
contains all files to exist during each build step, even if they have been 
modified or deleted.

```sh
# Let's see how we can find what's inside the layers
> docker image --help

Usage:  docker image COMMAND

Manage images

Commands:
  build       Build an image from a Dockerfile
  history     Show the history of an image
  import      Import the contents from a tarball to create a filesystem image
  inspect     Display detailed information on one or more images
  load        Load an image from a tar archive or STDIN
  ls          List images
  prune       Remove unused images
  pull        Pull an image or a repository from a registry
  push        Push an image or a repository to a registry
  rm          Remove one or more images
  save        Save one or more images to a tar archive (streamed to STDOUT by default)
  tag         Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE

Run 'docker image COMMAND --help' for more information on a command.

# This command will export a Docker image and its layers
> docker image save -o onions.tar downunderctf/onions
```

We can now open up this image archive, inspect each individual layer, and
find our missing flag.jpg!

```
DUCTF{P33L_B4CK_TH3_L4Y3RS}
```
