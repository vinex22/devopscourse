terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "3.22.0"
    }
  }
}

provider "azurerm" {
  subscription_id = "c2113b96-767a-4d7f-b0a1-a6c33443c4e4"
  #client_id       = "ed5d6ac4-de15-4a24-b5d3-61812c9e9941"
  #client_secret   = "HOl7Q~23UVXp4J1SlBTsQQSR~dMk2CTsNERWH"
  #tenant_id       = "70c0f6d9-7f3b-4425-a6b6-09b47643ec58"
  features {}
}


locals {
  resource_group="vinex2212"
  location="East Asia"
}

data "azurerm_subnet" "SubnetA" {
  name                 = "SubnetA"
  virtual_network_name = azurerm_virtual_network.app_network.name
  resource_group_name  = local.resource_group
}



resource "azurerm_virtual_network" "app_network" {
  name                = "app-network"
  location            = local.location
  resource_group_name = local.resource_group
  address_space       = ["10.0.0.0/16"]

  subnet {
    name           = "SubnetA"
    address_prefix = "10.0.1.0/24"
  }  
}

resource "azurerm_network_interface" "app_interface" {
  name                = "app-interface"
  location            = local.location
  resource_group_name = local.resource_group

  ip_configuration {
    name                          = "internal"
    subnet_id                     = data.azurerm_subnet.SubnetA.id
    private_ip_address_allocation = "Dynamic"
  }

  depends_on = [
    azurerm_virtual_network.app_network
  ]
}

resource "azurerm_windows_virtual_machine" "app_vm" {
  name                = "appvm"
  resource_group_name = local.resource_group
  location            = local.location
  size                = "Standard_D2s_v3"
  admin_username      = "demousr"
  admin_password      = "Azure@123"
  network_interface_ids = [
    azurerm_network_interface.app_interface.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }

  depends_on = [
    azurerm_network_interface.app_interface
  ]
}
