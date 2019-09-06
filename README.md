# gostsclient

Først startes docker-compose i testenv - man venter på, at den kommer op

Dernæst kan der bygges lokalt i roden: 
```

docker build --network testenv_gostsclient -t lokal/stsclient .
```

Afvikler tests op mod sts der kører i docker-compose
