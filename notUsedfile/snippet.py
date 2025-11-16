# import requests, json
#
# url = "https://dev-api.taxbuddy.com/itr/swagger/config"   # same URL you used
# headers = {"Authorization": "Bearer YOUR_TOKEN"}
#
# swagger = requests.get(url, headers=headers).json()
#
# print(swagger.keys())
#
# # Check how one path looks
# first_path = list(swagger["paths"].keys())[0]
# print("\nSample Path:", first_path)
# print(json.dumps(swagger["paths"][first_path], indent=2))


import requests
import json

url = "https://dev-api.taxbuddy.com/itr/swagger/config"   # your config URL
headers = {"Authorization": "Bearer eyJraWQiOiJZa2tEMzVPVXpDazNhZU45WGJIczM1cndITGoxamplVzRoSkttSG1iTlBrPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyYTYzYzA1My04ZDQzLTQyNGItOTI5ZS0wNjllYjAxNzhlOGYiLCJldmVudF9pZCI6ImY5MDdjMDJmLTBlYmYtNGFlNy1iNmM5LWE5Y2M4MzQyYmZmYSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3NjMyMDc0OTMsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aC0xLmFtYXpvbmF3cy5jb21cL2FwLXNvdXRoLTFfVjVzTzNkY1VWIiwiZXhwIjoxNzYzMjE0MDQxLCJpYXQiOjE3NjMyMTA0NDEsImp0aSI6IjdmYjM3ZjE0LTVjNzgtNDIzZC1iZTdkLTdiMzMzYThiZDQwMSIsImNsaWVudF9pZCI6IjQ5Y2EwYmpwNHJvcmdkcGl2YjFrOWxidjY1IiwidXNlcm5hbWUiOiIyYTYzYzA1My04ZDQzLTQyNGItOTI5ZS0wNjllYjAxNzhlOGYifQ.UdRlvfEMcssPkkK0S0t4KyTYgkKpyfFvvILN0lJ98CPRsU5HGwGDGTTY-4w0ItKgMBrwc3-lMAgaFoYxMKSuRvz0TadD_a29ccpa7IGy3s9xL-EnXois6R6FDdtA6WEyZFuTo4hT4wnbjp16XcKGI-oIckV8cWTZiwm0nL9bkIT4COE37maS0dYpkTMvSEXKgZT3PEjLXSEXVA2-6ZB7YfVSm0ClLC4eKYFNMKQ4d0t1E68lWWtQUivjsX9V3kUg-GZVd8qoj4X1O78vKbdtIJZ37kcclrKxy72iNuHf4z0zPTAvvRIb1H5FM3RnKeFCygdoLksOTNOYYW2Ms9mAPA"}

swagger_config = requests.get(url, headers=headers).json()

print("Swagger Spec URL:", swagger_config["url"])

