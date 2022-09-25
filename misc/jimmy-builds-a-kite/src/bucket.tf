# ~~=== Variabels ===~~~
variable "credentials_file" {}
variable "project" {}
variable "region" {}
variable "zone" {}
variable "bucket_name" {}

variable "public_files" {
  type = map(string)
  default = {
    # sourcefile = destfile
    "src/index.html" = "index.html",
    "src/adventure.py" = "adventure.py",
    "src/404.html"   = "404.html",
  }
}

variable "private_files" {
  type = map(string)
  default = {
    # sourcefile = destfile
    "src/private.html" = "private.html",
    "src/flag.txt"     = "flag.txt",
  }
}

# ~~~=== Setup Terraform ===~~~

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.34.0"
    }
  }
}

provider "google" {
  credentials = file(var.credentials_file)

  project = var.project
  region  = var.region
  zone    = var.zone
}

# ~~~=== Bucket ===~~~

resource "google_storage_bucket" "static_site" {
  name     = var.bucket_name
  location = var.region
}

resource "google_storage_bucket_access_control" "image-store-acl" {
  bucket = google_storage_bucket.static_site.name
  role = "READER"
  entity = "allUsers"
}

# ~~~=== Service Account ===~~~

resource "google_service_account" "cicd_service_account" {
  account_id   = "buildkite-agent"
  display_name = "A service account for the CI/CD pipeline."
}

resource "google_service_account_key" "private_service_account_key" {
  service_account_id = google_service_account.cicd_service_account.name
}


# ~~~=== credentials.json ===~~~

resource "google_storage_bucket_object" "public_key_object" {
  name    = "credentials.json"
  bucket  = google_storage_bucket.static_site.name
  content = base64decode(google_service_account_key.private_service_account_key.private_key)
}

resource "google_storage_object_access_control" "public_key_object_acl" {
  object = "credentials.json"
  bucket = google_storage_bucket.static_site.name
  role = "READER"
  entity = "allUsers"
}

# ~~~=== Public Files ===~~~

resource "google_storage_bucket_object" "public_objects" {
  for_each = var.public_files
  name     = each.value
  source   = "${path.module}/${each.key}"
  bucket   = google_storage_bucket.static_site.name
}

resource "google_storage_object_access_control" "public_objects_acl" {
  for_each = var.public_files
  object = each.value
  bucket = google_storage_bucket.static_site.name
  role = "READER"
  entity = "allUsers"
}

# ~~~=== Private Files ===~~~

resource "google_storage_bucket_object" "private_objects" {
  for_each = var.private_files
  name     = each.value
  source   = "${path.module}/${each.key}"
  bucket   = google_storage_bucket.static_site.name
}

resource "google_storage_object_access_control" "private_objects_acl" {
  for_each = var.private_files
  object = each.value
  bucket = google_storage_bucket.static_site.name
  role = "READER"
  entity = "user-${google_service_account.cicd_service_account.email}"
}
