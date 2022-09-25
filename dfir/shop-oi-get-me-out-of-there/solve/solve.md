By Looking at the logs you Identify that there is a "/changepassword" URL which redirects you to /login?ref=<B64 String>

By correlating the time of the "/changepassword" event and the change password email being sent to the admin account you can identify which password change correlates to the admin acccount. 

Additionally all of this activity is being conducted by the same suspicious IP that was doing login bruteforcing in the "Shop-Knock Knock Knock" Challenge.


Once you know which password change is related to the admin you can base64 decode the login ref and you'll notice that you get "md5Hash:md5Hash".

After cracking the hash using crackstation you'll find the two strings correlating to oldPassword:newPassword

All the other accounts which were broken into had the password changed to the same thing hence you can infer which is new and which is old