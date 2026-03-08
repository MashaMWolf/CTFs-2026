#WEBCHAL1

##Context

We are given a link to ```https://webchal1.vercel.app/```. This leads to a notetaking app which allows a user to fetch information from a URL and save it as a note. The goal is to find the flag using this method. 

##Methodology 

Seeing that we could request information from the server, my thoughts immediately go to server-side request forgery. I tested the payload ```https://webchal1.vercel.app/admin/flag.txt``` and it worked. Two notes 
were created: one with the flag and another with the html of the page. 

##Flag

``` TACHYON{5SrF_inj3ct10N_c0ol_123wed3} ```
