const config = require('../../config/config');
require('should');
const async = require('async');
const { By } = require('selenium-webdriver');
const chromeDriver = require('chromedriver');

// Documentation for the selenium JS webdriver: https://code.google.com/p/selenium/wiki/WebDriverJs
const seleniumWebdriver = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const test = require('selenium-webdriver/testing');
const proxy = require('selenium-webdriver/proxy');

const { path } = chromeDriver;
const service = new chrome.ServiceBuilder(path).build();

// SUT is an acronym for System Under Test.
const sutProtocol = 'http://';
const zapTargetApp = `${sutProtocol}${config.get('sut.hostIp')}:${config.get('sut.port')}/`;
const zapOptions = {
  proxy: (`${sutProtocol}${config.get('zap.hostIp')}:${config.get('zap.port')}/`),
  targetApp: zapTargetApp
};
const ZapClient = require('zaproxy');

const zaproxy = new ZapClient(zapOptions);
const zapTargetAppRoute = 'profile';
const zapTargetAppAndRoute = zapTargetApp + zapTargetAppRoute;
const zapApiKey = config.get('zap.apiKey');
const fs = require('fs');

const state = {
  description: '',
  error: null
};

const sutUserName = 'user1';
const sutUserPassword = 'User1_123';
let webDriver;

chrome.setDefaultService(service);

// Easiest way to understand how this works and go through the steps is to
// setup authentication for a user using Zap manually first
// using the following link: https://github.com/zaproxy/zaproxy/wiki/FAQformauth
// Then browse the Zap API viewing the existing manual setup through the views. Use that to formulate your code.
// Another link I found useful: // http://stackoverflow.com/questions/27596775/zap-authentication-using-api-calls
test.before(function beforeProfile() {
  this.timeout(20000);
  webDriver = new seleniumWebdriver.Builder()
    .withCapabilities(seleniumWebdriver.Capabilities.chrome())
    // http://code.tutsplus.com/tutorials/an-introduction-to-webdriver-using-the-javascript-bindings--cms-21855
    // Proxy all requests through Zap before using Zap to find vulnerabilities,
    // otherwise Zap will say: "URL not found in the scan tree".
    .setProxy(proxy.manual({
      http: `${config.get('zap.hostIp')}:${config.get('zap.port')}`
    }))
    .build();
  webDriver.getWindowHandle();
  webDriver.get(zapTargetApp);
  webDriver.sleep(1000);
  webDriver.findElement(By.name('userName')).sendKeys(sutUserName);
  webDriver.findElement(By.name('password')).sendKeys(sutUserPassword);
  webDriver.sleep(1000);
  webDriver.findElement({
    tagName: 'button',
    type: 'submit'
  }).click();
  webDriver.sleep(1000);
  webDriver.get(zapTargetAppAndRoute);
  webDriver.sleep(1000);
  webDriver.findElement(By.name('firstName')).sendKeys('seleniumJohn');
  webDriver.findElement(By.name('lastName')).sendKeys('seleniumDoe');
  webDriver.findElement(By.name('ssn')).sendKeys('seleniumSSN');
  webDriver.findElement(By.name('dob')).sendKeys('12/23/5678');
  webDriver.findElement(By.name('bankAcc')).sendKeys('seleniumBankAcc');
  webDriver.findElement(By.name('bankRouting')).sendKeys('0198212#');
  webDriver.findElement(By.name('address')).sendKeys('seleniumAddress');
  webDriver.findElement(By.name('submit')).click();
  webDriver.sleep(1000);
});
test.after(function afterProfile() {
  const overWrite = true;
  this.timeout(10000);
  webDriver.quit();
  zaproxy.core.newSession('new NodeGoat session', overWrite, zapApiKey, () => {});
  // zaproxy.core.shutdown(zapApiKey, function () {});
});


test.describe(`${zapTargetAppRoute} regression test suite`, function profileSuite() {
  this.timeout(0);

  // Links that were useful for getting up and running:
  // http://simpleprogrammer.com/2014/02/03/selenium-with-node-js/
  // http://www.vapidspace.com/coding/2014/02/08/automating-selenium-tests-with-grunt-and-mocha/
  // http://bites.goodeggs.com/posts/selenium-webdriver-nodejs-tutorial/
  test.it('Should not exceed the decided threshold of vulnerabilities known to Zap', (done) => {
    const contextId = 1;
    let userId;
    const maxChildren = 1;
    const alertThreshold = 3;
    let numberOfAlerts;
    let scanId;
    let zapInProgressIntervalId;
    // Todo: Let's do something with resultsFromAllAsyncSeriesFunctions.
    const onCompletion = (error, resultsFromAllAsyncSeriesFunctions) => {
      if (!error) {
        // eslint-disable-next-line no-console
        console.log(resultsFromAllAsyncSeriesFunctions[resultsFromAllAsyncSeriesFunctions.length - 1].description);
      } else throw error;
      if (numberOfAlerts > alertThreshold) {
        // eslint-disable-next-line no-console
        console.log(`Search the generated report for "/${zapTargetAppRoute}" to see the ${numberOfAlerts - alertThreshold} vulnerabilities that exceed the user defined threshold of: ${alertThreshold}`);
      }
      numberOfAlerts.should.be.lessThanOrEqual(alertThreshold);
      done();
    };


    async.series([

      function newContext(newContext1Done) {
        zaproxy.context.newContext('NodeGoat Context', zapApiKey, (err, resp) => {
          console.log(`Response from newContext: ${resp}`); // eslint-disable-line no-console
          newContext1Done(state.error);
        });
      },
      function spider(spiderDone) {
        zaproxy.spider.scan(zapTargetApp, maxChildren, zapApiKey, (err, resp) => {
          console.log(`Response from spider: ${resp}`); // eslint-disable-line no-console
          spiderDone(state.error, state);
        });
      },
      function includeInZapContext(includeInZapContextDone) {
        // Inform Zap how to authenticate itself.
        zaproxy.context.includeInContext('NodeGoat Context', zapTargetApp, zapApiKey, (err, resp) => {
          console.log(`Response from includeInContext: ${resp}`); // eslint-disable-line no-console
          includeInZapContextDone(state.error);
        });
      },
      function setAuthenticationMethod(setAuthenticationMethodDone) {
        zaproxy.authentication.setAuthenticationMethod(
          contextId,
          'formBasedAuthentication',
          // Only the 'userName' onwards must be URL encoded. URL encoding entire line doesn't work.
          `loginUrl=${zapTargetApp}login&loginRequestData=userName%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D%26_csrf%3D`,
          zapApiKey,
          (err, resp) => {
            console.log(`Response from setAuthenticationMethod: ${resp}`); // eslint-disable-line no-console
            setAuthenticationMethodDone(state.error);
          }
        );
      },
      function setLoggedInIndicator(setLoggedInIndicatorDone) {
        // contextId, loggedInIndicatorRegex
        zaproxy.authentication.setLoggedInIndicator(
          contextId,
          '<p>Moved Temporarily. Redirecting to <a href="/dashboard">/dashboard</a></p>',
          zapApiKey,
          (err, resp) => {
            console.log(`Response from setLoggedInIndicator: ${resp}`); // eslint-disable-line no-console
            setLoggedInIndicatorDone(state.error);
          }
        );
      },
      function setForcedUserModeEnabled(setForcedUserModeEnabledDone) {
        const enabled = true;
        zaproxy.forcedUser.setForcedUserModeEnabled(enabled, zapApiKey, (err, resp) => {
          console.log(`Response from setForcedUserModeEnabled: ${resp}`); // eslint-disable-line no-console
          setForcedUserModeEnabledDone(state.error);
        });
      },
      function newUser(newUserDone) {
        zaproxy.users.newUser(contextId, sutUserName, zapApiKey, (err, resp) => {
          // Todo: check userId.
          this.userId = resp.userId;
          console.log(`Response from newUser: ${resp}`); // eslint-disable-line no-console
          newUserDone(state.error);
        });
      },
      function setForcedUser(setForcedUserDone) {
        zaproxy.forcedUser.setForcedUser(contextId, userId, zapApiKey, (err, resp) => {
          console.log(`Response from setForcedUser: ${resp}`); // eslint-disable-line no-console
          setForcedUserDone(state.error);
        });
      },
      function setAuthenticationCredentials(setAuthenticationCredentialsDone) {
        zaproxy.users.setAuthenticationCredentials(
          contextId,
          userId,
          `username=${sutUserName}&password=${sutUserPassword}`,
          zapApiKey,
          (err, resp) => {
            console.log(`Response from setAuthenticationCredentials: ${resp}`); // eslint-disable-line no-console
            setAuthenticationCredentialsDone(state.error);
          }
        );
      },
      function setUserEnabled(setUserEnabledDone) { // User should already be enabled?
        const enabled = true;
        zaproxy.users.setUserEnabled(contextId, userId, enabled, zapApiKey, (err, resp) => {
          console.log(`Response from setUserEnabled: ${resp}`); // eslint-disable-line no-console
          setUserEnabledDone(state.error);
        });
      },
      function spiderAsUserForRoot(spiderAsUserForDone) {
        zaproxy.spider.scanAsUser(zapTargetApp, contextId, userId, maxChildren, zapApiKey, (err, resp) => {
          console.log(`Response from scanAsUser: ${resp}`); // eslint-disable-line no-console
          spiderAsUserForDone(state.error);
        });
      },
      function activeScan(activeScanDone) {
        zaproxy.ascan.scan(
          zapTargetAppAndRoute,
          true,
          false,
          '',
          'POST',
          'firstName=JohnseleniumJohn&lastName=DoeseleniumDoe&ssn=seleniumSSN&dob=12/23/5678&bankAcc=seleniumBankAcc&bankRouting=0198212#&address=seleniumAddress&_csrf=&submit=',
          zapApiKey,
          (err, resp) => {
            let statusValue;
            let zapError;

            scanId = resp.scan;

            function status() {
              zaproxy.ascan.status(scanId, (statusErr, statusResp) => {
                if (statusResp) statusValue = statusResp.status;
                if (statusErr) zapError = (statusErr.code === 'ECONNREFUSED') ? statusErr : '';
                zaproxy.core.numberOfAlerts(zapTargetAppAndRoute, (numberOfAlertsErr, numberOfAlertsResp) => {
                  if (numberOfAlertsResp) {
                    ({ numberOfAlerts } = numberOfAlertsResp);
                  }
                  // else console.log(err);
                  console.log(`Scan ${scanId} is ${statusValue}% complete with ${numberOfAlerts} alerts.`); // eslint-disable-line no-console
                });
              });
            }
            zapInProgressIntervalId = setInterval(() => {
              status();
              if (zapError && statusValue !== String(100)) {
                console.log('Canceling test. Zap API is unreachible.'); // eslint-disable-line no-console
                clearInterval(zapInProgressIntervalId);
                activeScanDone(zapError);
              } else if (statusValue === String(100)) {
                console.log(`We are finishing scan ${scanId}. Please see the report for further details.`); // eslint-disable-line no-console
                clearInterval(zapInProgressIntervalId);
                status();
                console.log('About to write report.'); // eslint-disable-line no-console
                zaproxy.core.htmlreport(zapApiKey, (htmlreportErr, htmlreportResp) => {
                  const date = new Date();
                  const reportPath = `${__dirname}/report_${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}-${date.getHours()}-${date.getMinutes()}.html`;
                  console.log(`Writing report to ${reportPath}`); // eslint-disable-line no-console
                  fs.writeFile(reportPath, htmlreportResp, (writeFileErr) => {
                    if (writeFileErr) console.log(writeFileErr); // eslint-disable-line no-console
                    activeScanDone(state.error, state);
                  });
                });
              }
            }, config.get('zap.apiFeedbackSpeed'));
          }
        );
      }
    ], onCompletion);
  });
});
