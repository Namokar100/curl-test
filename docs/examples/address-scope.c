/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * HTTP GET to an IPv6 address with specific scope
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#if !defined(_WIN32) && !defined(MSDOS) && !defined(__AMIGA__)
#include <net/if.h>
#endif

int main(void)
{
#if !defined(_WIN32) && !defined(MSDOS) && !defined(__AMIGA__)
  /* Windows/MS-DOS users need to find how to use if_nametoindex() */
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    long my_scope_id;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    my_scope_id = (long)if_nametoindex("eth0");
    curl_easy_setopt(curl, CURLOPT_ADDRESS_SCOPE, my_scope_id);

    /* Perform the request, res gets the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
#endif
  return 0;
}
