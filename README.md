This is a Basic structure of the firewall project we will be working on.
I have not yet added the data files upon which the randomforest model has been trained due to size constraint.
Install the required dependencies and run the backend_app and waf using following commands 
FOR BACKEND_APP:
cd backend_app
python app.py
FOR WAF:
cd waf
python app.py
The server will be runnnig on the local host for now and all the requests will be logged to mongodb server running locally so make sure to t=run the mongodb server on local host before testing the project via compass or terminal.
Once the servers are running try sending request to local hosts using following 
http://localhost:5000 ---this should show "Welcome to the REAL backend!"
http://localhost:5000/search  ---this should show "Search endpoint reached"
http://localhost:5000/login -d "username=admin' OR 1=1 --&password=123  ---this should show 403 Forbidden due to waf 
 
