Front End
=========

#### Testing the Container

```shell
$ docker build . -t web:latest
$ docker run -it --rm -p 3001:3000 -e CHOKIDAR_USEPOLLING=true -e PORT=3000 web:latest
```
