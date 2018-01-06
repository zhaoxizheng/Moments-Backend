# Moments-Backend

The project is the backend of a geo-index based social network.

It designed a scable service in Go to handle main functions of user register, sign up and post media data.
- Utilized ElasticSearch (GCE) to handle geo-location based searches so that users can search nearby posts within a specified distance.
- Used Google Cloud Storage(GCS) to store unstructured media data such as images and videos.
- Used token-based authentication to veerify user identity.

Also, another part is consisted of Java to handle offline analysis. The service first saved user posts to Google Bigtable and then dumped data to BigQuery for user behavior analysis or keyword spam detection. 
