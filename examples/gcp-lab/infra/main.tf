# Small, cheap GCP lab to try tfminder and its drift scan for real.
# Cost: a bucket, a topic and a firewall rule on an empty VPC are free or cents per month.
# Always finish with: tfminder plan lab --destroy  ->  approve  ->  apply

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "lab" {
  name                    = "tfminder-lab"
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "iap_ssh" {
  name          = "tfminder-lab-iap-ssh"
  network       = google_compute_network.lab.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"] # IAP TCP forwarding only
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_storage_bucket" "artifacts" {
  name                        = "${var.project_id}-tfminder-lab"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  versioning {
    enabled = true
  }
}

resource "google_pubsub_topic" "events" {
  name = "tfminder-lab-events"
}
