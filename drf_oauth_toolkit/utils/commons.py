from rest_framework.views import APIView


class PublicApi(APIView):
    authentication_classes = ()
    permission_classes = ()
