#include "dispatch.h"

#include <pcap.h>

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>

#include "analysis.h"

#define MAX_DISPATCH_JOBS 8

// This mutex represents the resource of the PCAP packet buffer
static pthread_mutex_t pcap_packet_mtx = PTHREAD_MUTEX_INITIALIZER;
// This variable tracks whether resource is copied or not.
static int pcap_packet_copied;
// This condition allows signalling when packet is copied
static pthread_cond_t pcap_packet_copy_cond = PTHREAD_COND_INITIALIZER;

// This mutex protects all the job-tracking resources
static pthread_mutex_t job_tracking_mtx = PTHREAD_MUTEX_INITIALIZER;
// These are the pthread_t's that represent the jobs
static pthread_t dispatch_jobs[MAX_DISPATCH_JOBS];
// We keep track of the number of active jobs so we know when we need to wait
// for a thread death
static size_t active_jobs = 0;
// This condition variable indicates when a job dies so the main thread knows
// it can join a thread when the max number of jobs are being used
static pthread_cond_t job_dying = PTHREAD_COND_INITIALIZER;
// This array keeps track of job states
static u_char dispatch_job_state[MAX_DISPATCH_JOBS] = {0};

enum {
  JOB_DEAD = 0,
  JOB_DYING,
  JOB_ALIVE
};

// This struct describes the parameters to thread_dispatch_job
struct Job_parameters {
  const struct pcap_pkthdr *header;
  const unsigned char      *packet;
  int                      verbose;
  size_t                   thread_num;
};

// This is the function called by individual job threads
static void * thread_dispatch_job(void *const user_data) {
  const struct Job_parameters *const p = user_data;

  assert(!pthread_mutex_lock(&pcap_packet_mtx));
    // Create thread-local copy of everything
    const struct pcap_pkthdr thread_header = *p->header;
    unsigned char *const thread_packet = malloc(thread_header.len);
    memcpy(thread_packet, p->packet, thread_header.len);
    const int verbose = p->verbose;
    const size_t thread_num = p->thread_num;

    // Set packet copied state
    pcap_packet_copied = 1;
  assert(!pthread_mutex_unlock(&pcap_packet_mtx));

  // Signal we're done with packet
  assert(!pthread_cond_signal(&pcap_packet_copy_cond));

  // Now we can do work in our own special world where everything works
  // (except globals)
  analyse(&thread_header, thread_packet, verbose);

  // Cleanup
  free(thread_packet);

  // Before we die, we're supposed to close the door on the way out
  assert(!pthread_mutex_lock(&job_tracking_mtx));
    --active_jobs;
    dispatch_job_state[thread_num] = JOB_DYING;
  assert(!pthread_mutex_unlock(&job_tracking_mtx));

  // Signal that we're dying
  assert(!pthread_cond_signal(&job_dying));

  return NULL;
}

// Split work as it comes in between as many threads as are available
void dispatch(
  const struct pcap_pkthdr *const header,
  const unsigned char *const      packet,
  const int                       verbose
) {
  size_t thread_num;
  struct Job_parameters params;

  // Check number of active jobs
  assert(!pthread_mutex_lock(&job_tracking_mtx));
    // If there is not enough room, wait for a death
    while (active_jobs >= MAX_DISPATCH_JOBS) {
      assert(!pthread_cond_wait(&job_dying, &job_tracking_mtx));
    }
    ++active_jobs;
    // Find empty thread data slot
    for (thread_num = 0; thread_num < MAX_DISPATCH_JOBS; ++thread_num) {
      if (dispatch_job_state[thread_num] == JOB_DEAD) {
        break;
      } else if (dispatch_job_state[thread_num] == JOB_DYING) {
        assert(!pthread_join(dispatch_jobs[thread_num], NULL));
        break;
      }
    }
    assert(thread_num != MAX_DISPATCH_JOBS); // this actually shouldn't happen
    // Create a new thread
    dispatch_job_state[thread_num] = JOB_ALIVE;
    pcap_packet_copied = 0;
    params = (struct Job_parameters){header, packet, verbose, thread_num};
    assert(!pthread_create(
      dispatch_jobs + thread_num,
      NULL,
      thread_dispatch_job,
      &params
    ));
  assert(!pthread_mutex_unlock(&job_tracking_mtx));

  // Check that packet data has been copied safely
  assert(!pthread_mutex_lock(&pcap_packet_mtx));
    while (!pcap_packet_copied) {
      assert(!pthread_cond_wait(&pcap_packet_copy_cond, &pcap_packet_mtx));
    }
  assert(!pthread_mutex_unlock(&pcap_packet_mtx));
}
