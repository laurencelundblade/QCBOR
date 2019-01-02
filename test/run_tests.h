
/*==============================================================================
 run_tests.c -- test aggregator and results reporting

 Created 9/30/18.

 Copyright (c) 2018, Laurence Lundblade.
 All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * The name "Laurence Lundblade" may not be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ==============================================================================*/


/**
 @brief Type for function to output a text string

 @param[in] szString   The string to output
 @param[in] pOutCtx    A context pointer; NULL if not needed

 This is a prototype of a function to be passed to run_tests() to
 output text strings.  This can be implemented with stdio (if
 available) using a straight call to fputs() where the FILE *
 is passed as the ctx.
*/
typedef void (*OutputStringCB)(const char *szString, void *pOutCtx);


/**
 @brief Runs the QCBOR tests

 @param[in] szTestNames    An argv-style list of test names to run. If
                           empty, all are run.
 @param[in] pfOutput         Function that is called to output text strings.
 @param[in] pOutCtx        Context pointer passed to output function.
 @param[out] pNumTestsRun  Returns the number of tests run. May be NULL.

 @return The number of tests that failed. Zero means overall success.
 */
int RunTests(const char *szTestNames[], OutputStringCB pfOutput, void *pOutCtx, int *pNumTestsRun);


/**
 @brief Print sizes of encoder / decoder contexts.

 @param[in] pfOutput         Function that is called to output text strings.
 @param[in] pOutCtx        Context pointer passed to output function.
 */
void PrintSizes(OutputStringCB pfOutput, void *pOutCtx);

