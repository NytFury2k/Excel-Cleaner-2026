COLUMN_METADATA={
    #Identity Fields

    "email":{"type":"email", "required": True, "unique_identity": True, "aliases":
              ["email", "email address", "e-mail", "mail","email id","e mail","work email","personal email"]},
    "phone": {"type": "phone", "required": False, "unique_identity": True, "aliases": 
              ["phone","phone number","mobile","mobile number","contact number", "cell","cell number","telephone","tel","whatsapp","fax","work phone","home phone","alt phone","alternate number","contact","alternate phone"]},
    "url": {"type": "url", "required": False, "unique_identity": False, "aliases":
             ["website", "linkedin", "linkedin url", "website url","profile link", "website link","linkedin link","profile url","instagram","twitter","faecbook","github","portfolio","social","social media","link","fb","x","handle"]},
    "name": {"type": "text", "required": False, "unique_identity": False, "aliases": 
             ["name", "full name", "first name", "last name", "fname","lname","given name","surname","middle name","display name","contact name","alias"]},
    "company": {"type": "text", "required": False, "unique_identity": False, "aliases": 
                ["comapny", "company name", "organization", "organization name","organisation","organisation name","employer","firm","business","brand","account name","client name","client"]},
    "id": {"type": "numeric", "required": False, "unique_identity": True, "aliases": 
           ["id", "user id", "employee id", "customer id"]},
    "date": {"type": "date", "required": False, "unique_identity": False, "aliases":
              ["dob", "birthday", "birth date", "date", "created at", "created date","date created", "creation date", "signup date","joined date","registration date","updated at","modified date","last updated","closed date","due date","deadline","expiry date","appointment date","scheduled date","start date","end date"]},
    
}

def get_column_type(column_name):
    col_lower = column_name.lower().strip()
    for key, meta in COLUMN_METADATA.items():
        if col_lower in meta["aliases"]:
            return meta["type"]
    return "text"