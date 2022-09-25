output "url" {
  description = "Website URL"
  value       = google_storage_bucket.static_site.self_link
}

output "service_account" {
  value = google_service_account.cicd_service_account.email
}