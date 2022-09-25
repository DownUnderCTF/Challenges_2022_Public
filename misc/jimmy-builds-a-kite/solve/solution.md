# Solution

Go to the website:
```
https://jimmy-adventure.storage.googleapis.com/index.html
```

You will be greeted with a pseudo terminal, chat-box thingy that starts talking to you. You can try to interact but all the text is on a timer and no interactions are actually implemented.

Instead, look at where this website is beign hosted.

```
storage.googleapis.com
```

This is Google's bucket API, more spesifically their SOAP api. 
> What does that mean? For this challenge - nothing. If you're curious though [read this](https://www.redhat.com/en/topics/integration/whats-the-difference-between-soap-rest).

You can list all files in the bucket by going to the root url (not the index.html file)

```
https://jimmy-adventure.storage.googleapis.com/
```

This will be a bunch of ugly XML. If you read through it though you'll find a `/flag.txt` entry. Success! But if we try to go to it we get an error: `Anonymous caller does not have storage.objects.get access to the Google Cloud Storage object.`

Damn. Looks like we need some sort of credentials.

`/credentials.json`

Oh hey credentials!

These are for a gcp service account. To activate them:

```
wget https://jimmy-adventure.storage.googleapis.com/credentials.json

gcloud auth activate-service-account --key-file=credentials.json
```

Now lets try to pull that file. For this we can use the cli utilities for GCP.
```
gsutil cat gs://jimmy-adventure/flag.txt
```