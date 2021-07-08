import pandas as pd
import os
from sys import exit

class AKERProj(object):
  def __init__(self, csv_file=None):
    self.threat_model = None
    
    self.SPs = dict()
    
    if csv_file != None:
      self.from_csv(csv_file)
    
    self.__exp_total = 0
    self.__ift_total = 0
    self.__trc_total = 0
    
  def set_threat_model(self, u_tm):
    '''
    Sets the threat model for the AKER security verification project.
    If a threat model already exists, it will be replaced by this threat model.
    Input:
    - u_tm: a string stating the threat model 
    Output:
    - None
    '''
    if type(u_tm) == str:
      self.threat_model = u_tm
    else:
      raise TypeError("u_tm must be a string")
      
  def get_threat_model(self):
    '''
    Returns the threat model for the AKER security verification project.
    Input:
    - None 
    Output:
    - a string stating the provided threat model or None if no threat model\
    has been set.
    '''
    return self.threat_model

  def add_sec_prop(self, u_sp):
    '''
    Adds a SecProp object to the AKER security verification project.
    The SecProp object's ID will be used to add it to the security property dictionary.
    Input:
    - u_sp: a SecProp object (with a valid and unique ID) 
    Output:
    - None
    '''

    if type(u_sp) != type(SecProp()):
      raise TypeError("u_sp must be a SecProp object".format(i, type(u_sp)))
    if u_sp.get_id() in self.SPs.keys():
      raise KeyError("When added to an AKERProj, SecProp objects must have unique IDs.\
      A SecProp with the ID = \'{}\' already exists.".format(u_sp.get_id()))

    self.SPs[u_sp.get_id()] = u_sp
    
  def remove_sec_prop(self, sp_id):
    '''
    Removes a SecProp object from the AKER security verification project.
    The provided SecProp object ID will be used to remove it from the \
    security property dictionary.
    Input:
    - sp_id: a string containing a SecProp object ID 
    Output:
    - None
    '''

    if type(sp_id) != str:
      raise TypeError("sp_id must be a string".format(i, type(sp_id)))

    del self.SPs[sp_id]
  
  def import_helper(self,i_str):
    if i_str == "nan":
      return None
    elif isinstance(i_str, list) and (len(i_str) == 1):
      if i_str == "nan":
        return None
    else:
      return i_str
    
  def from_csv(self, csv_file):
    df = pd.read_csv(csv_file, dtype = str)
    cols = list(df.columns)
    if len(cols) >= 5:
      c1 = cols[0] == 'SP ID'
      c2 = cols[1] == 'Related CWEs'
      c3 = cols[2] == 'SP Requirement'
      c4 = cols[3] == 'SP Specification Template'
      c5 = cols[4] == 'SP Type'
      c6 = None
      if len(cols) >= 6:
        c6 = cols[5] == 'SP Assets'

      if c1 and c2 and c3 and c4 and c5:
        for i in range(df.shape[0]):
          p_id   = self.import_helper(str(df.iloc[i][0]))
          cwes   = self.import_helper(str(df.iloc[i][1]).strip().replace(" ","").split(","))
          req    = self.import_helper(str(df.iloc[i][2]))
          temp   = self.import_helper(str(df.iloc[i][3]))
          p_type = self.import_helper(str(df.iloc[i][4]))
          assets = None
          if c6:
            assets = eval(self.import_helper(str(df.iloc[i][5])))
          self.add_sec_prop(SecProp(p_id, cwes, req, temp, p_type, assets))
      else:
        #TODO: Improve warning and provide a template csv somewhere
        raise RuntimeWarning("An empty AKERProj object has been created because \
        the provided CSV does not follow the expected column layout")
    else:
      #TODO: Improve warning and provide a template csv somewhere
      raise RuntimeWarning("An empty AKERProj object has been created because \
      the provided CSV does not follow the expected column layout")
      
  def to_csv(self, output_csv="aker_summary.csv", with_assets=False):
    proj_dict = dict()
    proj_dict['SP ID'                    ] = list()
    proj_dict['Related CWEs'             ] = list()
    proj_dict['SP Requirement'           ] = list()
    proj_dict['SP Specification Template'] = list()
    proj_dict['SP Type'                  ] = list()
    if with_assets:
      proj_dict['SP Assets'                ] = list()    
    proj_dict['Total SPs After Expanding'] = list()

    for sp_id in self.SPs.keys():
      sp = self.SPs[sp_id]
      proj_dict['SP ID'                    ] += [str(sp.id)]
      proj_dict['Related CWEs'             ] += [", ".join([str(cwe_id) for cwe_id in sp.CWEs])] if (sp.CWEs != None) else [""]
      proj_dict['SP Requirement'           ] += [sp.requirement] if (sp.requirement != None) else [""]
      proj_dict['SP Specification Template'] += [sp.template]
      proj_dict['SP Type'                  ] += [sp.type]
      if with_assets:
        proj_dict['SP Assets'                ] += [sp.assets]
      proj_dict['Total SPs After Expanding'] += [sp.expansion_total]

    df = pd.DataFrame(proj_dict)
    df = df.set_index('SP ID')
    df.to_csv(output_csv)

  def genDivider(self, as_file):
    print("////////////////////////////////////////",file=as_file)
    print("////////////////////////////////////////",file=as_file)
    print("",file=as_file)
  
  def util_gen_output_dir(self, func_name, output_path):
    # Create default output directory 
    if output_path == None:
      output_path = os.getcwd() + "/aker_sps"
      if not os.path.exists(output_path):
        print("[{}] No output_path specified. Creating output at {}".format(func_name,output_path))
        os.makedirs(output_path)
      else:
        count = 1
        while os.path.exists(output_path+"_"+str(count)):
          count += 1
        output_path = output_path+"_"+str(count)
        print("[{}] No output_path specified. Creating output at {}".format(func_name,output_path))
        os.makedirs(output_path)

    # Create specified output directory  
    else:
      if not os.path.exists(output_path):
        os.makedirs(output_path)
      else:
        real_path = os.path.realpath(output_path)
        print("[{}] Error: The specified output_path ({}) already exists. Cannot create output directory at {}".format(func_name,output_path,real_path))
        exit(1)

    return output_path
  
  def expand_templates(self, output_dir=None, combined=False):
    self.__exp_total = 0
    self.__ift_total = 0
    self.__trc_total = 0
    
    g_output_dir = self.util_gen_output_dir("AKERProj.expand_templates", output_dir)
    for i,sp in enumerate(self.SPs.values()):
      if combined:
        sp.expand_template(g_output_dir+"/SP_all.as".format(i), file_mode="a", suppress_console_print=True)
      else:
        sp.expand_template(g_output_dir+"/SP_{}.as".format(sp.get_id()), suppress_console_print=True)
      
      if (sp.get_expansion_total() != None):
        self.__exp_total += sp.get_expansion_total()
        if sp.get_type() == "IFT":
          self.__ift_total += sp.get_expansion_total()
        else:
          self.__trc_total += sp.get_expansion_total()
  
  def get_expansion_stats(self, decis=4):
    pad_str = (lambda val,fc,al,w: f'{val:{fc}{al}{w}}')
    
    tot_p = 100
    ift_p = (self.__ift_total/self.__exp_total)*100
    trc_p = 100 - ift_p
    
    tot_p = pad_str(tot_p," ",">",decis)
    ift_p = pad_str(str(ift_p)[:decis], " ", ">", decis)
    trc_p = pad_str(str(trc_p)[:decis], " ", ">", decis)
    
    stats  = "AKERProj Template Expansion Stats\n"
    stats += "|-- Specific SPs Generated\n"
    stats += "|   |-- Total = {} ({}%) | IFT = {} ({}%) | Trace = {} ({}%)\n".format(\
                                                                                   self.__exp_total, tot_p,\
                                                                                   self.__ift_total,\
                                                                                   ift_p,\
                                                                                   self.__trc_total,\
                                                                                   trc_p)
    stats += "|-- Breakdown by SP_ID\n"
    
    tot_w = len(str(self.__exp_total))
    ift_w = len(str(self.__ift_total))
    trc_w = len(str(self.__trc_total))
    
    for sp in self.SPs.values():
      tot = sp.get_expansion_total()
      ift = 0
      trc = 0
      if sp.get_type() == "IFT":
        ift = sp.get_expansion_total()
      else:
        trc = sp.get_expansion_total()
      
      p_tot_p = (tot/self.__exp_total)*100
      p_ift_p = (ift/self.__ift_total)*100
      p_trc_p = (trc/self.__trc_total)*100
     
      # Pad the strings with spaces for a nicer layout
      tot = pad_str(tot," ",">",tot_w)
      ift = pad_str(ift," ",">",ift_w)
      trc = pad_str(trc," ",">",trc_w)
      p_tot_p = pad_str(str(p_tot_p)[:decis], " ", ">", decis)
      p_ift_p = pad_str(str(p_ift_p)[:decis], " ", ">", decis)
      p_trc_p = pad_str(str(p_trc_p)[:decis], " ", ">", decis)
      
      stats += "    |-- Total = {} ({}%) | IFT = {} ({}%) | Trace = {} ({}%) | SP-ID = {}\n".format(tot, p_tot_p, ift, p_ift_p, trc, p_trc_p,sp.id)
      
    return stats
  
    
class SecProp(object):
  def __init__(self, sp_id=None, cwes=None, req=None, temp=None, p_type=None, assets=None):
    if sp_id != None:
      self.set_id(sp_id)
    else:
      self.id = sp_id
    
    if cwes != None:
      self.set_CWEs(cwes)
    else:
      self.CWEs = cwes
    
    if req != None:
      self.set_requirement(req)
    else:
      self.requirement = req
    
    if temp != None:
      self.set_template(temp)
    else:
      self.template = temp
    
    if p_type != None:
      self.set_type(p_type)
    else:
      self.type = p_type
    
    if assets != None:
      self.set_assets(assets)
    else:
      self.assets = assets
    
    self.expansion_total = None
    
    self.results = None
    
  def set_id(self, u_id):
    '''
    Sets the id string for the security property.
    If the string already exists, it will be replaced by this string.
    Input:
    - u_id: a string stating the property's id
    Output:
    - None
    '''
    if type(u_id) == str:
      self.id = u_id
    else:
      raise TypeError("u_id must be a string")
      
  def get_id(self):
    '''
    Returns the id string for the security property.
    Input:
    - None 
    Output:
    - a string stating the property's id\
    or None if no string has been set
    '''
    return self.id
  
  def set_CWEs(self, u_cwes):
    '''
    Sets the CWE-IDs list for the security property.
    If the list already exists, it will be replaced by this threat model.
    Input:
    - u_cwes: a list where each element is a string containing a CWE's ID number
    Output:
    - None
    '''
    if type(u_cwes) == list:
      for i,cwe in enumerate(u_cwes):
        if type(cwe) != str:
          raise TypeError("CWE-IDs list contains a non-string\
          at index = {}. All CWE-IDs must be a string".format(i, type(cwe)))
      self.CWEs = u_cwes
    else:
      raise TypeError("u_cwes must be a list")
      
  def get_CWEs(self):
    '''
    Returns the CWE-IDs list for the security property.
    Input:
    - None 
    Output:
    - a list where each element is a string containing a CWE's ID number\
    or None if no list has been set
    '''
    return self.CWEs
  
  def set_requirement(self, u_req):
    '''
    Sets the security requirement string for the security property.
    If the string already exists, it will be replaced by this string.
    Input:
    - u_req: a string stating a plain-language security\
    requirement
    Output:
    - None
    '''
    if type(u_req) == str:
      self.requirement = u_req
    else:
      raise TypeError("u_req must be a string")
      
  def get_requirement(self):
    '''
    Returns the security requirement string for the security property.
    Input:
    - None 
    Output:
    - a string stating a plain-language security\
    requirement or None if no string has been set
    '''
    return self.requirement
   
  def set_template(self, u_temp):
    '''
    Sets the security property template string for the security property.
    If the string already exists, it will be replaced by this string.
    Input:
    - u_temps: a string specifying a security property template
    Output:
    - None
    '''
    if type(u_temp) == str:
      self.template = u_temp
      prop_type = 'IFT' if '=/=>' in u_temp else 'Trace'
      self.set_type(prop_type)
    else:
      raise TypeError("u_temp must be a string")
      
  def get_template(self):
    '''
    Returns the security property template string for the security property.
    Input:
    - None 
    Output:
    - a string specifying a security property template\
    or None if no string has been set
    '''
    return self.template
  
  def set_type(self, u_type):
    '''
    Sets the security property type string for the security property.
    If the string already exists, it will be replaced by this string.
    Input:
    - u_temps: a string specifying the type of the security property
    Output:
    - None
    '''
    if type(u_type) == str:
      self.type = u_type
    else:
      raise TypeError("u_type must be a string")
      
  def get_type(self):
    '''
    Returns the security property type string for the security property.
    Input:
    - None 
    Output:
    - a string specifying the type of the security property\
    or None if no string has been set
    '''
    return self.type  
  
  def set_assets(self, u_assets, deep_type_check=True):
    '''
    Sets the assets list for the security property.
    If the list already exists, it will be replaced by this list.
    Input:
    - u_assets: a list where each element is a tuple of n strings \
    (n is equal to the number of generic signals/values to replace)
    - deep_type_check: a boolean indicating whether or not to perform\
    a complete type check on all elements and subelements of u_assets.\
    Default is True but setting to False can increase performance for \
    very large lists of assets.
    Output:
    - None
    '''
    if type(u_assets) == list:
      if deep_type_check:
        for i,a in enumerate(u_assets):
          if (type(a) != tuple):
            raise TypeError("Assets list contains a non-tuple\
            at index = {}. Each element of the assets list must be a tuple".format(i, type(a)))
          #TODO Finish Deep Type Check for Tuple size and elements
      self.assets = u_assets
    else:
      raise TypeError("u_assets must be a list")
      
  def get_assets(self):
    '''
    Returns the assets list for the security property.
    Input:
    - None 
    Output:
    - a list where each element is a tuple of n strings \
    (n is equal to the number of generic signals/values to replace)\
    or None if no list has been set
    '''
    return self.assets
  
  def get_expansion_total(self):
    '''
    Returns the total number of expanded security properties for the security property.
    Input:
    - None 
    Output:
    - an integer specifying the total number of expanded security properties\
    or None if expansion has not occured yet
    '''
    return self.expansion_total
  
  def expand_template(self, output_file=None, file_mode='w', suppress_console_print=False):
    if (self.id != None) and (self.template != None) and (self.assets != None):
      #Replace generic signals with assets
      template = "\n".join(self.template.split("\n")[1:]).encode('utf-8','ignore').decode("utf-8")
      
      file = None
      if output_file != None:
        if (type(output_file) == str):
          file = open(output_file, mode=file_mode)
          if self.requirement != None:
            req = self.get_requirement().encode('utf-8','ignore').decode("utf-8")
            print(req, end="\n\n", file=file)
        else:
          raise TypeError("output_file must be a string defining a file path")
      
      
      for i, asset_tuple in enumerate(self.assets):
        split_prop = str.split(template, "`")
        sig_in_split_index = 1
        for asset in asset_tuple:
          split_prop[sig_in_split_index] = asset
          sig_in_split_index += 2
        new_sp = "".join(split_prop)

        #Replace generic property label
        prop_label = "SP{}_{}: assert iflow(".format(self.id, i)
        new_sp = str.split(new_sp, "assert iflow(")
        final_sp = prop_label+new_sp[1]
        if (file != None) or (suppress_console_print == False):
          print(final_sp, end="\n\n", file=file)
    
      if (file != None):
        file.close()
      self.expansion_total = len(self.assets)
      
  
  def __str__(self):
    
    cwes   = ", ".join([str(cwe_id) for cwe_id in self.CWEs]) if (self.CWEs != None) else ""
    req    = self.requirement if (self.requirement != None) else ""
    temp   = self.template if (self.template != None) else ""
    p_type = self.type if (self.type != None) else ""
    assets = self.assets if (self.assets != None) else ""
    exp_t  = self.expansion_total if (self.expansion_total != None) else "NA"
    
    
    sp_str = ""
    sp_str += "-- ID = \'{}\'".format(self.id)
    sp_str += "-- CWEs = \'{}\'".format(cwes)
    sp_str += "-- Requirement = \'{}\'".format(req)
    sp_str += "-- Template = \'{}\'".format(temp)
    sp_str += "-- Type = \'{}\'".format(p_type)
    sp_str += "-- Assets = \'{}\'".format(assets)
    sp_str += "-- Expansion Total = \'{}\'".format(exp_t)
    
    return sp_str
      
  def __eq__(self, operand):
    '''Overrides the default implementation of __eq__'''
    if isinstance(operand, SecProp):
      result = self.id == operand.id              
      result = result and (self.CWEs            == operand.CWEs           ) 
      result = result and (self.requirement     == operand.requirement    ) 
      result = result and (self.template        == operand.template       ) 
      result = result and (self.type            == operand.type           ) 
      result = result and (self.assets          == operand.assets         ) 
      result = result and (self.expansion_total == operand.expansion_total) 
      result = result and (self.results         == operand.results        )
      return result
    return False