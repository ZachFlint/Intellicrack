{{ fullname | escape | underline}}

{% if modules %}
.. automodule:: {{ fullname }}
   :no-index:

.. rubric:: Submodules

.. autosummary::
   :toctree:
   :recursive:
{% for item in modules %}
   {{ item }}
{%- endfor %}
{% else %}
.. automodule:: {{ fullname }}
{% endif %}
