# About "admin" directory (for developers)
This `bin/hamcore/wwwroot/admin/` directory is the web contents root of the embedded HTML5 web administration console: `http://<vpn_server_host>:<port>/admin/`.

Currently there is only the `default/` sub directory. It is corresponding to `http://<vpn_server_host>:<port>/admin/default/`.


The `/admin/index.html` file always redirects all clients to the `/admin/default/`.


If you are willing to develop the web-based administration console you have two choices:

1. Modify and improve the `/admin/default/` project.


2. Create your entirely new web project in the `/admin/NEW_PATH_HERE/` directory. You can choose the unique directory name instead of `NEW_PATH_HERE` on the above directory path.
  

If you want to create an independent new web project, the choice #2 is the best way. You can do anything freely in your new directory. In such a case, please edit the `/admin/index.html` not to redirect to the `/admin/default/index.html` automatically. Instead, put the list of the systems for each of sub directories in the `/admin/index.html` so that the user can choose which system to use.


  

