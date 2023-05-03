# Real-time chat-backend-repo

# Installation

* You should have Go installed on your computer.

* You have a redis instance,websocket and npm installed on your pc.

* You should have a gcp service account and it's json file should be present in your local machine.

# Features

* It allows user to login,logout and register with the help of JWT Tokens.

* It allows user to chat with each other in the real-time

* It allows user to share only document(.pdf file) with each other

# Requirments

* Golang(1.16 or higher)

* Redis(v8.0 or higher)

* Websockets

*GCP

# Installation
* Clone the Repository
```bash
git clone https://github.com/Sachingeek125/chat-backend-repo.git
```

# Run
* For running this project Just follow below commands:
 ```bash
go build
go run main.go
```

* By running these the server will start on the 8080 port number.Now here comes the question of how to test the real-time chat functionality

* So first you have to register yourself and then you have to login into your account with the help of credentilas then it will create the JWT Tokens.

* Now you have to connect with websocket in order to test real-time functionality with below commands.
 ```bash
wscat -c ws://localhost:8080/ws/{receiver_number} -H "Authorization: Bearer <your-jwt-token>"
```

* If receiver_number is correct and it's exists in the database of redis and in addition to that if jwt token is correct then you can connected and talk with the receiver in real time, but the condition is that receiver also have to stay connected with websocket in order to get and send real-time messages.(this was all for text messages, but what for document sharing?)

* For document sharing: you have the endpoint which you can run on a postman with POST method and then you have to upload the document here also which we want to share(but keep in the mind that you have to authorize yourself as a user with Authorization Header in the postman)
```bash
http://localhost:8080//send/document/{receiver_number}
```

* you can view the shared document and viewed document also by /inboxDocument and /outboxDocument endpoints just you have to authorize yourself by authorization header.

* Thank you for viewing my project, hope it helps you.
