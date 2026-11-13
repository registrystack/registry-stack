# Package and return the QField project

Use QGIS with the QFieldSync plugin and a local QField client.
The cable workflow was exercised with QGIS 4.2.1, QFieldSync 4.23.3 and the QField 4.3.7 Linux client.
QField opens a local copy of the project and its GeoPackage.
After collection, QFieldSync applies that copy's tracked edits to the original PostGIS layers.

## Connect the native project

1. Install the [QFieldSync plugin](https://plugins.qgis.org/plugins/qfieldsync/) in QGIS.
2. Create a PostgreSQL connection service named `qfield_intake` for the collection database. Use your institution's connection and credential handling.
3. Give that service's login `USAGE` on `field_collection` and the required read and write permissions on the `sites`, `boundaries` and `contacts` tables.
   The adapter uses a separate projection reader described in the [example guide](../README.md).
4. Open [project.qgs](project.qgs) in QGIS. Check that all three layers open and the site form displays the **Boundary** and **Contacts** relations.
   The project contains a service name. Its layers are marked **Offline editing** for cable packaging.
   Keep all three layers on the same PostgreSQL service. The return uses one transaction, with the child foreign keys checked at commit.
   Keep the hidden `expected_boundary_id` and `expected_contact_ids` fields in the site form layout so QField evaluates their defaults.

## Collect and return

1. Use **Package for QField** in the QFieldSync toolbar and choose an empty output directory.
   Include the whole project directory when you transfer it to the collection device.
2. In QField, open the packaged project. Turn on digitizing and add a feature to **sites**.
   Place the point, enter the site name and save the draft.
3. Open the saved site form in edit mode. Add one polygon from the **Boundary** relation and two to eight rows from **Contacts**.
   Save each child before marking the site ready.
4. Set **Ready** and save.
   The form evaluates the related record IDs, which the source later checks against the returned rows.
5. Close the project and transfer the complete directory back to QGIS.
   Open the original online project and run **Synchronize from QField** with the returned project.
6. Check the source-side `field_collection.site_intake_status` view before running Adapter.
   The example's source database exposes the site when its ready state, geometry and declared children agree.
   If the expected site is missing or ineligible, inspect the source result and reconcile using the saved package before repeating a return.

Keep a copy of a returned package until its source synchronization and intake are accounted for.
Choose an appropriate capture extent and offline map for your deployment, and qualify the exact QGIS, QFieldSync and QField versions your collectors use.
Check that QField opens at the intended extent before collecting data.
[QFieldSync cable packaging and synchronization](https://docs.qfield.org/get-started/tutorials/get-started-qfs/).
