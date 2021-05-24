Front End
=========

#### Testing the Container

```shell
$ docker build . -t web:latest
$ docker run -it --rm -v ${PWD}:/app -v /app/node_modules -p 3001:3000 -e CHOKIDAR_USEPOLLING=true web:latest
```
