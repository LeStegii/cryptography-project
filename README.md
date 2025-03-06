# Cryptography Engineering Project
Client-Server architecture project for Cryptography Engineering course at University of Kassel.

- Registration/Login using salted and peppered passwords
- X3DH for key exchanges
- Double Ratchet for exchanging messages

## How to install and run?
1. Create a virtual environment (optional)
2. Run `pip install -r requirements.txt` to install the dependencies.
3. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
    1. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
    2. Leave everything else as is.
4. Put the `server.pem` certificate in both `client` and `server` directory.
5. Put the `server.key` certificate in the `server` directory.
6. Run `python3 server.py` in the `server` directory to start the server\*.
7. Run `python3 client.py` in the `client` directory to start one or more clients.

\* Note:
Depending on where you run the project, you might have to set the `PYTHONPATH` to the root directory of the project. 
For this, go to the root directory of the project and run `export PYTHONPATH=$(pwd)` (Linux) or `set PYTHONPATH=%CD%` (Windows).
Using an IDE like IntelliJ usually doesn't require this step.

If there is an error like `[Errno 98] Address already in use`, wait for your OS to release the port or change the port in the `server.py` and `client.py` files.

## How to use?
When registering for the first time, enter your username and press enter.
The server will then ask you for your password for registration and after the registration is done, you can login.
For logging in, enter your password and wait for the server to accept it.
When already registered, the password has to be entered only once.

- After logging in, type `exit` to exit the program.
- Using `init <user>` you can initialize a chat with another user.
- Chat messages can be sent with `msg <user> <message>`. For this, a chat has to be initialized first.
- If you want to reset your data with another user or the server (e.g. due to a data sync error), use `reset <user>` or `reset server`.  This will delete all the data from the required databases and allows a fresh restart.

## Example output

### Registration/Login

#### Client registering
```
[15:03:59] MainThread: Connected to server localhost:25567.
Enter your username: Paul
[15:04:02] MainThread: Connected to server localhost:25567 as Paul.
[15:04:02] Thread-1 (receive_message): User not registered.
Enter your new password: 123
[15:04:04] Thread-1 (receive_message): Computing keys...
[15:04:04] Thread-1 (receive_message): Sending registration request to server...
[15:04:04] Thread-1 (receive_message): Received salt and pepper from server.
[15:04:04] Thread-1 (receive_message): User registered successfully. You can now login.
Enter your password: 123
[15:04:05] Thread-1 (receive_message): User logged in successfully.
[15:04:05] Thread-2 (send_messages): You can now send messages to the server.
[15:04:05] Thread-2 (send_messages): Type 'exit' to close the connection.
[15:04:05] Thread-2 (send_messages): Type 'init <target>' to initiate a key exchange and open a chat.
[15:04:05] Thread-2 (send_messages): Type 'msg <target> <message>' to chat.
[15:04:05] Thread-2 (send_messages): Type 'reset <target>' to reset the chat with a user.
[15:04:05] Thread-2 (send_messages): Type 'reset server' to delete your account.
exit
[15:04:08] Thread-2 (send_messages): Closing connection.
[15:04:09] Thread-1 (receive_message): Connection closed.
```

#### Client logging in
```
[15:05:16] MainThread: Connected to server localhost:25567.
Enter your username: Paul
[15:05:18] MainThread: Connected to server localhost:25567 as Paul.
[15:05:18] Thread-1 (receive_message): User registered. Requesting salt from client...
Received salt for login. Please enter your password: 123
[15:05:19] Thread-1 (receive_message): User logged in successfully.
[15:05:19] Thread-2 (send_messages): You can now send messages to the server.
[15:05:19] Thread-2 (send_messages): Type 'exit' to close the connection.
[15:05:19] Thread-2 (send_messages): Type 'init <target>' to initiate a key exchange and open a chat.
[15:05:19] Thread-2 (send_messages): Type 'msg <target> <message>' to chat.
[15:05:19] Thread-2 (send_messages): Type 'reset <target>' to reset the chat with a user.
[15:05:19] Thread-2 (send_messages): Type 'reset server' to delete your account.
```

#### Logging in with an invalid name
```
[15:07:00] MainThread: Connected to server localhost:25567.
Enter your username: #
[15:07:05] MainThread: Connected to server localhost:25567 as #.
[15:07:05] Thread-1 (receive_message): Connection closed.
```

#### Logging in with an invalid password
```
[15:07:30] MainThread: Connected to server localhost:25567.
Enter your username: Paul
[15:07:31] MainThread: Connected to server localhost:25567 as Paul.
[15:07:32] Thread-1 (receive_message): User registered. Requesting salt from client...
Received salt for login. Please enter your password: 345
[15:07:35] Thread-1 (receive_message): Error logging in: Password incorrect.
```

#### Connection while already logged in
```
[15:08:01] MainThread: Connected to server localhost:25567.
Enter your username: Paul
[15:08:03] MainThread: Connected to server localhost:25567 as Paul.
[15:08:03] Thread-1 (receive_message): Received error from server: A user with this name is already connected.
```

### The server during all these actions

```
[15:03:54] MainThread: Server started on localhost:25567
[15:03:59] MainThread: New connection from ('127.0.0.1', 46650)
[15:03:59] Thread-1 (handle_client): Handling client ('127.0.0.1', 46650). Checking it's identity.
[15:04:02] Thread-1 (handle_client): Received bytes.
[15:04:02] Thread-1 (handle_client): Paul (('127.0.0.1', 46650)) sent a status request, User is currently not registered.
[15:04:04] Thread-1 (handle_client): Paul (('127.0.0.1', 46650)) is trying to register.
[15:04:04] Thread-1 (handle_client): Creating salt for Paul (('127.0.0.1', 46650)).
[15:04:04] Thread-1 (handle_client): Creating pepper for Paul (('127.0.0.1', 46650)).
[15:04:04] Thread-1 (handle_client): Saving password for Paul (('127.0.0.1', 46650)). Sending salt to client.
[15:04:05] Thread-1 (handle_client): Paul (('127.0.0.1', 46650)) sent login request, checking attempts...
[15:04:05] Thread-1 (handle_client): Checking password...
[15:04:05] Thread-1 (handle_client): Paul's (('127.0.0.1', 46650)) password is correct. User is now logged in.
[15:04:09] Thread-1 (handle_client): Received empty byte message from ('127.0.0.1', 46650). Closing connection.
[15:04:09] Thread-1 (handle_client): Connection with ('127.0.0.1', 46650) closed.
[15:05:16] MainThread: New connection from ('127.0.0.1', 39788)
[15:05:16] Thread-2 (handle_client): Handling client ('127.0.0.1', 39788). Checking it's identity.
[15:05:18] Thread-2 (handle_client): Received bytes.
[15:05:18] Thread-2 (handle_client): Paul (('127.0.0.1', 39788)) sent a status request, User is registered.
[15:05:18] Thread-2 (handle_client): ('127.0.0.1', 39788) sent REQUEST_SALT as Paul. Sending salt.
[15:05:19] Thread-2 (handle_client): Paul (('127.0.0.1', 39788)) sent login request, checking attempts...
[15:05:19] Thread-2 (handle_client): Checking password...
[15:05:19] Thread-2 (handle_client): Paul's (('127.0.0.1', 39788)) password is correct. User is now logged in.
[15:06:50] Thread-2 (handle_client): Received empty byte message from ('127.0.0.1', 39788). Closing connection.
[15:06:50] Thread-2 (handle_client): Connection with ('127.0.0.1', 39788) closed.
[15:07:00] MainThread: New connection from ('127.0.0.1', 39926)
[15:07:00] Thread-4 (handle_client): Handling client ('127.0.0.1', 39926). Checking it's identity.
[15:07:05] Thread-4 (handle_client): Received bytes.
[15:07:05] Thread-4 (handle_client): ('127.0.0.1', 39926)'s first message couldn't be decoded.
[15:07:05] Thread-4 (handle_client): Connection with ('127.0.0.1', 39926) closed.
[15:07:30] MainThread: New connection from ('127.0.0.1', 52526)
[15:07:30] Thread-5 (handle_client): Handling client ('127.0.0.1', 52526). Checking it's identity.
[15:07:32] Thread-5 (handle_client): Received bytes.
[15:07:32] Thread-5 (handle_client): Paul (('127.0.0.1', 52526)) sent a status request, User is registered.
[15:07:32] Thread-5 (handle_client): ('127.0.0.1', 52526) sent REQUEST_SALT as Paul. Sending salt.
[15:07:35] Thread-5 (handle_client): Paul (('127.0.0.1', 52526)) sent login request, checking attempts...
[15:07:35] Thread-5 (handle_client): Checking password...
[15:07:35] Thread-5 (handle_client): Paul's (('127.0.0.1', 52526)) password is incorrect!
[15:07:35] Thread-5 (handle_client): Received empty byte message from ('127.0.0.1', 52526). Closing connection.
[15:07:35] Thread-5 (handle_client): Connection with ('127.0.0.1', 52526) closed.
[15:07:54] MainThread: New connection from ('127.0.0.1', 49794)
[15:07:55] Thread-6 (handle_client): Handling client ('127.0.0.1', 49794). Checking it's identity.
[15:07:56] Thread-6 (handle_client): Received bytes.
[15:07:56] Thread-6 (handle_client): Paul (('127.0.0.1', 49794)) sent a status request, User is registered.
[15:07:56] Thread-6 (handle_client): ('127.0.0.1', 49794) sent REQUEST_SALT as Paul. Sending salt.
[15:07:57] Thread-6 (handle_client): Paul (('127.0.0.1', 49794)) sent login request, checking attempts...
[15:07:57] Thread-6 (handle_client): Checking password...
[15:07:57] Thread-6 (handle_client): Paul's (('127.0.0.1', 49794)) password is correct. User is now logged in.
[15:08:01] MainThread: New connection from ('127.0.0.1', 52518)
[15:08:01] Thread-7 (handle_client): Handling client ('127.0.0.1', 52518). Checking it's identity.
[15:08:03] Thread-7 (handle_client): Received bytes.
[15:08:03] Thread-7 (handle_client): ('127.0.0.1', 52518) tried to connect as Paul, but a user with this name is already connected.
[15:08:03] Thread-7 (handle_client): Connection with ('127.0.0.1', 52518) closed.
```

### Chatting


#### Sender (Paul)
```
[15:22:18] Thread-1 (receive_message): User logged in successfully.
[15:22:18] Thread-2 (send_messages): You can now send messages to the server.
...
msg Hans Hey!
[15:22:26] Thread-2 (send_messages): No shared secret found for Hans. Initiate a chat using 'init Hans'.
[15:22:26] Thread-2 (send_messages): Failed to send message.
init Hans
[15:22:30] Thread-2 (send_messages): Requesting key bundle for Hans...
[15:22:30] Thread-1 (receive_message): Computing shared secret...
[15:22:30] Thread-1 (receive_message): Sending reaction to server...
[15:22:30] Thread-1 (receive_message): Shared secret computed and saved for Hans.
msg Hans Hey!
msg Hans How are you? 
[15:22:48] Thread-1 (receive_message): Hans: Hey!
[15:22:56] Thread-1 (receive_message): Hans: I'm good thanks. How about you?
[15:23:09] Thread-1 (receive_message): Hans: Have to go offline now, will read your messages later.
msg Hans No Problem, this chat supports offline messages :D
exit
[15:23:38] Thread-2 (send_messages): Closing connection.
[15:23:39] Thread-1 (receive_message): Connection closed.
```

#### Receiver (Hans)
```
[15:24:32] Thread-1 (receive_message): User logged in successfully.
[15:24:32] Thread-2 (send_messages): You can now send messages to the server.
...
[15:22:30] Thread-1 (receive_message): Received a forwarded x3dh message for Hans from server.
[15:22:30] Thread-1 (receive_message): Succesfully computed shared secret with Paul.
[15:22:33] Thread-1 (receive_message): Paul: Hey!
[15:22:38] Thread-1 (receive_message): Paul: How are you?
msg Paul Hey!
msg Paul I'm good thanks. How about you?
msg Paul Have to go offline now, will read your messages later.
exit
[15:23:10] Thread-2 (send_messages): Closing connection.
[15:23:11] Thread-1 (receive_message): Connection closed.
...
[15:24:48] Thread-1 (receive_message): User logged in successfully.
[15:24:48] Thread-2 (send_messages): You can now send messages to the server.
...
[15:24:48] Thread-1 (receive_message): Paul: No Problem, this chat supports offline messages :D
```

### Empty OPKs

#### Receiver (Receiver is online)
```
[15:33:14] Thread-1 (receive_message): Received a forwarded x3dh message for Hans from server.
[15:33:14] Thread-1 (receive_message): No more one time prekeys left. Sending new ones to server.
[15:33:14] Thread-1 (receive_message): Succesfully computed shared secret with Paul.
[15:33:14] Thread-1 (receive_message): Server accepted new one time prekeys.
```

#### Sender (Receiver is offline)
```
init Hans
[15:34:54] Thread-2 (send_messages): Requesting key bundle for Hans...
[15:34:54] Thread-1 (receive_message): Failed to request key bundle: Hans doesn't have keys left and is offline.
```



### Resetting account

#### Resetter (Paul)
```
[15:27:29] Thread-1 (receive_message): User logged in successfully.
[15:27:29] Thread-2 (send_messages): You can now send messages to the server.
...
reset server
[15:27:33] Thread-2 (send_messages): Sending reset request to server for server.
[15:27:33] Thread-2 (send_messages): Account reset. Closing connection.
[15:27:33] Thread-1 (receive_message): Connection closed.
```

#### Other user (Hans)
```
[15:28:11] Thread-1 (receive_message): User logged in successfully.
[15:28:11] Thread-2 (send_messages): You can now send messages to the server.
...
[15:28:11] Thread-1 (receive_message): Received reset request from server.
[15:28:11] Thread-1 (receive_message): Deleted shared secret, chat and key bundle with Paul from the database.
```

#### Server
```
[15:27:33] Thread-5 (handle_client): Paul (('127.0.0.1', 36314)) sent a reset request.
[15:27:33] Thread-5 (handle_client): Error with client ('127.0.0.1', 36314): User reset.
[15:27:33] Thread-5 (handle_client): Connection with ('127.0.0.1', 36314) closed.
```

### Resetting chat

#### Resetter (Paul)
```
[15:30:18] Thread-1 (receive_message): Hans: Hi!
init Hans
[15:30:25] Thread-2 (send_messages): Already have shared secret with Hans. Use 'reset Hans' to reset or 'msg Hans <message>' to send a message.
reset Hans
[15:30:28] Thread-2 (send_messages): Sending reset request to server for Hans.
[15:30:28] Thread-2 (send_messages): Deleted shared secret, chat and key bundle with Hans from the database.
init Hans
[15:31:00] Thread-2 (send_messages): Requesting key bundle for Hans...
[15:31:00] Thread-1 (receive_message): Computing shared secret...
[15:31:00] Thread-1 (receive_message): Sending reaction to server...
[15:31:00] Thread-1 (receive_message): Shared secret computed and saved for Hans.

```

#### Other user (Hans)
```
msg Paul Hi!
[15:30:28] Thread-1 (receive_message): Received reset request from server.
[15:30:28] Thread-1 (receive_message): Deleted shared secret, chat and key bundle with Paul from the database.
[15:31:00] Thread-1 (receive_message): Received a forwarded x3dh message for Hans from server.
[15:31:00] Thread-1 (receive_message): Succesfully computed shared secret with Paul.
```