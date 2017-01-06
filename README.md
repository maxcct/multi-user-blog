# Multi-User Blog

Go to [hwapp123.appspot.com/signup](https://hwapp123.appspot.com/signup). Create an account. Use the blog.
If it isn't self-explanatory, it isn't working properly!

If hwapp123.appspot.com isn't live, navigate to the directory containing main.py in command
line/terminal, then enter `gcloud app deploy`. Enter 'Y' when prompted. That should get the
blog online.

To run the blog locally, you must have Google Cloud SDK installed. Navigate to the directory
containing main.py in command line/terminal, then enter:

```
python "[path to AppData]\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\dev_appserver.py" .
```

The appropriate path will vary depending on where exactly you have the Cloud SDK installed.
The commands required may also vary between operating systems.

If the local server was launched successfully, you should see a response such as this:

```
Starting module "default" running at: http://localhost:8080
```

You should then be able to access the blog at [localhost:8080/signup](http://localhost:8080/signup) in your browser.

**N.B.** Please note that the results of actions such as submitting a new post or liking a post may not
be apparent until the page is refreshed. I've looked into this and it appears to be an issue
with Google's Datastore: nothing I can do about it. Just manually refresh the page after such
actions, if necessary.
