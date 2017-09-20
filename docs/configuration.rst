Configuration
=============

This configuration section presents some configurations options options for logging, and other services such as InfluxDB and Grafana, if you are leveraging Docker.

Logging
-------

In this project, there is a file logging.yml, which you can set which logging level you are interested in. By default, the `root` logger is set with `INFO` level. If you need to debug, just raise this level.

.. note::
    The `DEBUG` level is very verbose at the moment, which is why logging rotate is enable by default. If you interested in debugging, watch out for the debug.log file.

InfluxDB
--------

The version of InfluxDB being utilized is 1.3. Essentially, most of the configuration is using the default parameters that are available in the official `influxdb` docker image.

Grafana
-------

This project is leveraging Grafana version 4.3.0. In order to use this container, you have to accomplish these two steps:

**1**. Configure the data source as InfluxDB:

Access this URL:

.. code:: shell

   http://localhost:3000

Click on `Add data source` and fill all the fields with these information:

.. code:: shell

    name: root
    Type: InfluxDB
    Url: http://localhost:8086
    Access: proxy
    Database: root
    user: admin
    password: admin

Click on `Save and Test`, you should see a success message.

.. WARNING::
    For production deployments, you should NOT use default credentials. Make sure you change this accordingly in the options and in the code.

**2**. Configure web-based dashboards according to our preference, or just import the template that is shipped with `ofp_sniffer`:

Access this URL:

.. code:: shell

    http://localhost:3000

Click on `Dasboards > Import > Upload json file`, and specify this file:

.. code:: shell

    ofp_sniffer/SDNLG_Dashboard.json

**3**. If you want to leverage Slack for notifications, you can setup certain thresholds on Grafana panes:

Clock on `Alerting > Notification Channels > New Channel` and specify these information:

.. code:: shell

    Name: Slack
    Type: Slack
    URL: <Set your Slack API bot's web hook URL here>
    Recepient: #your_notification_channel

.. note::

    For example, at AmLight, there is a #of_notifications channel utilized for OpenFlow notifications.
